defmodule Membrane.ICE.Endpoint2 do
  @moduledoc """
  """

  use Membrane.Endpoint

  require Membrane.Logger
  require Membrane.OpenTelemetry
  require Membrane.TelemetryMetrics

  alias Membrane.Funnel
  alias Membrane.ICE.Utils
  alias Membrane.RemoteStream
  alias Membrane.SRTP
  alias Membrane.TelemetryMetrics
  alias ExICE.ICEAgent

  @component_id 1
  @stream_id 1

  @payload_received_event [Membrane.ICE, :ice, :payload, :received]
  @payload_sent_event [Membrane.ICE, :ice, :payload, :sent]
  @request_received_event [Membrane.ICE, :stun, :request, :received]
  @response_sent_event [Membrane.ICE, :stun, :response, :sent]
  @indication_sent_event [Membrane.ICE, :stun, :indication, :sent]
  @ice_port_assigned [Membrane.ICE, :port, :assigned]
  @send_error_event [Membrane.ICE, :ice, :send_errors]
  @buffer_processing_time [Membrane.ICE, :ice, :buffer, :processing_time]

  @emitted_events [
    @payload_received_event,
    @payload_sent_event,
    @request_received_event,
    @response_sent_event,
    @indication_sent_event,
    @ice_port_assigned,
    @send_error_event,
    @buffer_processing_time
  ]

  @life_span_id "ice_endpoint.life_span"
  @dtls_handshake_span_id "ice_endpoint.dtls_handshake"

  def_options dtls?: [
                spec: boolean(),
                default: true,
                description: "`true`, if using DTLS Handshake, `false` otherwise"
              ],
              handshake_opts: [
                spec: keyword(),
                default: [],
                description:
                  "Options for `ExDTLS` module. They will be passed to `ExDTLS.start_link/1`"
              ],
              telemetry_label: [
                spec: TelemetryMetrics.label(),
                default: [],
                description: "Label passed to Membrane.TelemetryMetrics functions"
              ],
              trace_context: [
                spec: :list | any(),
                default: [],
                description: "Trace context for otel propagation"
              ],
              parent_span: [
                spec: :opentelemetry.span_ctx() | nil,
                default: nil,
                description: "Parent span of #{@life_span_id}"
              ]

  def_input_pad :input,
    availability: :on_request,
    accepted_format: _any,
    demand_mode: :auto

  def_output_pad :output,
    availability: :on_request,
    accepted_format: %RemoteStream{content_format: nil, type: :packetized},
    mode: :push

  @impl true
  def handle_init(_context, options) do
    %__MODULE__{
      dtls?: dtls?,
      handshake_opts: hsk_opts,
      telemetry_label: telemetry_label,
      trace_context: trace_context,
      parent_span: parent_span
    } = options

    if trace_context != [], do: Membrane.OpenTelemetry.attach(trace_context)
    start_span_opts = if parent_span, do: [parent_span: parent_span], else: []
    Membrane.OpenTelemetry.start_span(@life_span_id, start_span_opts)

    for event_name <- @emitted_events do
      TelemetryMetrics.register(event_name, telemetry_label)
    end

    state = %{
      id: to_string(Enum.map(1..10, fn _i -> Enum.random(?a..?z) end)),
      selected_alloc: nil,
      dtls?: dtls?,
      hsk_opts: hsk_opts,
      telemetry_label: telemetry_label,
      component_connected?: false,
      cached_hsk_packets: nil,
      component_ready?: false,
      pending_connection_ready?: false,
      connection_status_sent?: false,
      sdp_offer_arrived?: false,
      first_dtls_hsk_packet_arrived: false
    }

    {[], state}
  end

  @impl true
  def handle_playing(_ctx, %{dtls?: true} = state) do
    {:ok, dtls} = ExDTLS.start_link(state.hsk_opts)
    {:ok, fingerprint} = ExDTLS.get_cert_fingerprint(dtls)

    hsk_state = %{:dtls => dtls, :client_mode => state.hsk_opts[:client_mode]}

    {:ok, ice} = ICEAgent.start_link(:controlled, stun_servers: ["stun:stun.l.google.com:19302"])
    {:ok, ufrag, pwd} = ICEAgent.get_local_credentials(ice)

    state =
      Map.merge(state, %{
        ice: ice,
        handshake: %{state: hsk_state, status: :in_progress, keying_material_event: nil}
      })

    actions = [
      stream_format: {Pad.ref(:output, @component_id), %RemoteStream{type: :packetized}},
      notify_parent: {:handshake_init_data, @component_id, fingerprint},
      notify_parent: {:local_credentials, "#{ufrag} #{pwd}"}
    ]

    {actions, state}
  end

  @impl true
  def handle_pad_added(Pad.ref(:input, @component_id), ctx, state) do
    actions = maybe_send_keying_material_event(ctx, state)
    {actions, state}
  end

  @impl true
  def handle_pad_added(
        Pad.ref(:output, @component_id) = pad,
        ctx,
        %{dtls?: true, handshake: %{status: :finished}} = state
      ) do
    actions =
      maybe_send_stream_format(ctx) ++ [event: {pad, state.handshake.keying_material_event}]

    {actions, state}
  end

  @impl true
  def handle_pad_added(Pad.ref(:output, @component_id), ctx, state) do
    {maybe_send_stream_format(ctx), state}
  end

  @impl true
  def handle_write(
        Pad.ref(:input, @component_id),
        %Membrane.Buffer{payload: payload, metadata: metadata},
        _ctx,
        state
      ) do
    send_ice_payload(state.ice, payload, state.telemetry_label, Map.get(metadata, :timestamp))
    {[], state}
  end

  @impl true
  def handle_event(
        Pad.ref(:input, @component_id) = pad,
        %Funnel.NewInputEvent{},
        _ctx,
        %{dtls?: true, handshake: %{status: :finished}} = state
      ) do
    {[event: {pad, state.handshake.keying_material_event}], state}
  end

  @impl true
  def handle_event(_pad, _event, _ctx, state), do: {[], state}

  # TODO Use mocking turn server instead of this
  @impl true
  def handle_parent_notification(:test_get_pid, _ctx, state) do
    msg = {:test_get_pid, self()}
    {[notify_parent: msg], state}
  end

  @impl true
  def handle_parent_notification(:gather_candidates, _ctx, state) do
    :ok = ICEAgent.gather_candidates(state.ice)
    {[], state}
  end

  @impl true
  def handle_parent_notification({:set_remote_credentials, credentials}, _ctx, state)
      when state.component_connected? do
    [ice_ufrag, ice_pwd] = String.split(credentials)

    :ok = ICEAgent.set_remote_credentials(state.ice, ice_ufrag, ice_pwd)

    state =
      Map.merge(state, %{
        sdp_offer_arrived?: true,
        connection_status_sent?: true,
        pending_connection_ready?: false
      })

    Membrane.OpenTelemetry.add_event(@life_span_id, :component_ready)
    actions = [notify_parent: {:connection_ready, @stream_id, @component_id}]
    {actions, state}
  end

  @impl true
  def handle_parent_notification({:set_remote_credentials, credentials}, _ctx, state) do
    [ice_ufrag, ice_pwd] = String.split(credentials)
    :ok = ICEAgent.set_remote_credentials(state.ice, ice_ufrag, ice_pwd)
    state = Map.merge(state, %{sdp_offer_arrived?: true})
    {[], state}
  end

  @impl true
  def handle_parent_notification({:add_remote_candidate, candidate}, _ctx, state) do
    ICEAgent.add_remote_candidate(state.ice, candidate)
    {[], state}
  end

  @impl true
  def handle_parent_notification(:restart_stream, _ctx, state) do
    :ok = ICEAgent.restart(state.ice)
    {:ok, ufrag, pwd} = ICEAgent.get_local_credentials(state.ice)

    state =
      Map.merge(state, %{
        connection_status_sent?: false,
        sdp_offer_arrived?: false
      })

    Membrane.OpenTelemetry.add_event(@life_span_id, :restart_stream)

    credentials = "#{ufrag} #{pwd}"
    {[notify_parent: {:local_credentials, credentials}], state}
  end

  @impl true
  def handle_parent_notification(:peer_candidate_gathering_done, _ctx, state) do
    {[], state}
  end

  @impl true
  def handle_info({:ex_ice, _pid, {:new_candidate, cand}}, _ctx, state) do
    cand = "a=candidate:" <> cand
    actions = [notify_parent: {:new_candidate_full, cand}]
    {actions, state}
  end

  @impl true
  def handle_info({:ex_ice, _pid, :gathering_complete}, _ctx, state) do
    actions = [notify_parent: :candidate_gathering_done]
    {actions, state}
  end

  @impl true
  def handle_info({:DOWN, _ref, _process, alloc_pid, _reason}, _ctx, state) do
    alloc_span_id(alloc_pid)
    |> Membrane.OpenTelemetry.end_span()

    {[], state}
  end

  @impl true
  def handle_info({:ex_ice, _pid, {:data, payload}}, ctx, state) do
    # TelemetryMetrics.execute(
    #   @payload_received_event,
    #   %{bytes: byte_size(payload)},
    #   %{},
    #   state.telemetry_label
    # )

    if state.dtls? and Utils.is_dtls_hsk_packet(payload) do
      Membrane.Logger.info("Processing remote hsk packets")

      state =
        if state.first_dtls_hsk_packet_arrived do
          state
        else
          Membrane.OpenTelemetry.start_span(@dtls_handshake_span_id, parent_id: @life_span_id)
          %{state | first_dtls_hsk_packet_arrived: true}
        end

      ExDTLS.process(state.handshake.state.dtls, payload)
      |> handle_process_result(ctx, state)
    else
      out_pad = Pad.ref(:output, @component_id)

      actions =
        cond do
          not Map.has_key?(ctx.pads, out_pad) ->
            Membrane.Logger.warn(
              "No links for component: #{@component_id}. Ignoring incoming message."
            )

            []

          ctx.playback != :playing ->
            Membrane.Logger.debug(
              "Received message in playback state: #{ctx.playback}. Ignoring."
            )

            []

          true ->
            [
              buffer: {out_pad, %Membrane.Buffer{payload: payload, metadata: %{}}}
            ]
        end

      {actions, state}
    end
  end

  @impl true
  def handle_info({:ex_ice, _pid, :connected}, ctx, state) do
    Membrane.Logger.info("Connected")
    {state, actions} = select_alloc(ctx, state)
    {actions, %{state | component_connected?: true}}
  end

  @impl true
  def handle_info({:ex_ice, _pid, msg}, _ctx, state) do
    require Logger
    Logger.warn("#{inspect(msg)}")
    {[], state}
  end

  @impl true
  def handle_info({:retransmit, _dtls_pid, packets}, ctx, state) do
    # Treat retransmitted packets in the same way as regular handshake_packets
    handle_process_result({:handshake_packets, packets}, ctx, state)
  end

  @impl true
  def handle_info(msg, _ctx, state) do
    Membrane.Logger.warn("Received unknown message: #{inspect(msg)}")
    {[], state}
  end

  defp select_alloc(ctx, state) do
    {state, actions} =
      if state.dtls? == false or state.handshake.status == :finished do
        maybe_send_connection_ready(state)
      else
        Membrane.Logger.debug("Checking for cached handshake packets")

        if state.cached_hsk_packets == nil do
          Membrane.Logger.debug("Nothing to be sent for component: #{@component_id}")
        else
          Membrane.Logger.debug(
            "Sending cached handshake packets for component: #{@component_id}"
          )

          send_ice_payload(
            state.ice,
            state.cached_hsk_packets,
            state.telemetry_label
          )
        end

        with %{dtls?: true} <- state, %{dtls: dtls, client_mode: true} <- state.handshake.state do
          {:ok, packets} = ExDTLS.do_handshake(dtls)
          send_ice_payload(state.ice, packets, state.telemetry_label)
        else
          _state -> :ok
        end

        {state, actions} =
          if state.handshake.status == :finished do
            maybe_send_connection_ready(state)
          else
            {state, []}
          end

        {%{state | cached_hsk_packets: nil}, actions}
      end

    {state, keying_material_actions} = handle_component_state_ready(ctx, state)
    actions = keying_material_actions ++ actions
    {state, actions}
  end

  defp handle_process_result(:handshake_want_read, _ctx, state) do
    {[], state}
  end

  defp handle_process_result({:ok, _packets}, _ctx, state) do
    Membrane.Logger.warn("Got regular handshake packet. Ignoring for now.")
    {[], state}
  end

  defp handle_process_result({:handshake_packets, packets}, _ctx, state) do
    if state.component_connected? do
      Membrane.Logger.info("Sending hsk packets")
      send_ice_payload(state.ice, packets, state.telemetry_label)
      {[], state}
    else
      # if connection is not ready yet cache data
      # TODO maybe try to send?
      state = %{state | cached_hsk_packets: packets}
      {[], state}
    end
  end

  defp handle_process_result({:handshake_finished, hsk_data}, ctx, state),
    do: handle_end_of_hsk(hsk_data, ctx, state)

  defp handle_process_result({:handshake_finished, hsk_data, packets}, ctx, state) do
    send_ice_payload(state.ice, packets, state.telemetry_label)
    handle_end_of_hsk(hsk_data, ctx, state)
  end

  defp handle_process_result({:connection_closed, reason}, _ctx, state) do
    Membrane.Logger.debug("Connection closed, reason: #{inspect(reason)}. Ignoring for now.")
    {[], state}
  end

  defp handle_end_of_hsk(hsk_data, ctx, state) do
    Membrane.OpenTelemetry.end_span(@dtls_handshake_span_id)

    hsk_state = state.handshake.state
    event = to_srtp_keying_material_event(hsk_data)

    state =
      Map.put(state, :handshake, %{
        state: hsk_state,
        status: :finished,
        keying_material_event: event
      })

    {state, connection_ready_actions} = maybe_send_connection_ready(state)

    actions =
      connection_ready_actions ++
        maybe_send_keying_material_event(ctx, state) ++
        maybe_send_keying_material_to_output(ctx, state)

    {actions, state}
  end

  defp handle_component_state_ready(ctx, state) do
    state = %{state | component_ready?: true}
    actions = maybe_send_keying_material_event(ctx, state)
    {state, actions}
  end

  defp maybe_send_keying_material_event(ctx, state) do
    pad = Pad.ref(:input, @component_id)

    if state.dtls? and Map.has_key?(ctx.pads, pad) and state.component_ready? and
         state.handshake.status == :finished do
      [event: {pad, state.handshake.keying_material_event}]
    else
      []
    end
  end

  defp maybe_send_keying_material_to_output(ctx, state) do
    pad = Pad.ref(:output, @component_id)

    if Map.has_key?(ctx.pads, pad),
      do: [event: {pad, state.handshake.keying_material_event}],
      else: []
  end

  defp maybe_send_stream_format(ctx) do
    pad = Pad.ref(:output, @component_id)

    if ctx.playback == :playing do
      [stream_format: {pad, %RemoteStream{}}]
    else
      []
    end
  end

  defp maybe_send_connection_ready(
         %{connection_status_sent?: false, sdp_offer_arrived?: true} = state
       ) do
    state = %{state | connection_status_sent?: true}

    Membrane.OpenTelemetry.add_event(@life_span_id, :component_state_ready)
    actions = [notify_parent: {:connection_ready, @stream_id, @component_id}]

    {state, actions}
  end

  defp maybe_send_connection_ready(
         %{connection_status_sent?: false, sdp_offer_arrived?: false} = state
       ),
       do: {%{state | pending_connection_ready?: true}, []}

  defp maybe_send_connection_ready(state), do: {state, []}

  defp to_srtp_keying_material_event(handshake_data) do
    {local_keying_material, remote_keying_material, protection_profile} = handshake_data

    %SRTP.KeyingMaterialEvent{
      local_keying_material: local_keying_material,
      remote_keying_material: remote_keying_material,
      protection_profile: protection_profile
    }
  end

  defp send_ice_payload(ice, payload, telemetry_label, timestamp \\ nil) do
    TelemetryMetrics.execute(
      @payload_sent_event,
      %{bytes: byte_size(payload)},
      %{},
      telemetry_label
    )

    if timestamp do
      processing_time =
        (:erlang.monotonic_time() - timestamp) |> System.convert_time_unit(:native, :microsecond)

      TelemetryMetrics.execute(
        @buffer_processing_time,
        %{microseconds: processing_time},
        %{},
        telemetry_label
      )
    end

    :ok = ICEAgent.send_data(ice, payload)
  end

  # defp alloc_span_id(alloc_pid), do: "alloc_span:#{inspect(alloc_pid)}"
  defp alloc_span_id(alloc_pid), do: {:turn_allocation_span, alloc_pid}
end
