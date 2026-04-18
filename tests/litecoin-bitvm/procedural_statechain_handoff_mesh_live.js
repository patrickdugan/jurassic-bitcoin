const { runApplicationMesh } = require("./procedural_application_mesh_common");

runApplicationMesh("statechain_handoff")
  .then((payload) => {
    console.log("[procedural-statechain-handoff-mesh-live] SUCCESS");
    console.log(JSON.stringify(payload, null, 2));
  })
  .catch((err) => {
    console.error("[procedural-statechain-handoff-mesh-live] failed:", err && err.stack ? err.stack : err);
    process.exit(1);
  });
