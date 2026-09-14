export function createPanelState() {
  return {
    view: "dashboard",
    navigationGeneration: 0,
    me: null,
    clients: [],
    users: [],
    userFilter: "all",
    userQuery: "",
    mieruUsers: [],
    mieruService: { ready: false, revision: "" },
    naiveUsers: [],
    naiveService: { ready: false, host: "" },
    naiveFilter: "all",
    naiveQuery: "",
    versions: { enabled: false, components: {} },
    nodes: [],
    fleet: [],
    fleetSelection: "",
    fleetCommands: [],
    // Linked panels (Fleet v2): the open tab per node, the inventory of the nodes whose
    // «Пользователи» tab is open, and the last successful probe of the link dialog.
    nodeTab: {},
    nodeInventory: {},
    linkProbe: null,
    // Routing (v0.4): the targets table, the node × protocol on screen, and the editor's
    // draft/preview state (`routing`, built lazily by routing.js).
    routingTargets: [],
    routingNode: null,
    routingProtocol: null,
    routing: null,
    admins: [],
    keys: [],
    // The plaintext of a freshly created API key lives here only while #key-reveal is open.
    keyPlaintext: null,
    audit: {
      items: [],
      nextCursor: null,
      actor: "",
      action: "",
      target: "",
    },
  };
}

export function isCurrent(state, generation, viewName) {
  return state.navigationGeneration === generation && state.view === viewName;
}
