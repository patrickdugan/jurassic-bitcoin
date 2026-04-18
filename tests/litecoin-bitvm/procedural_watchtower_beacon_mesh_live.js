const { runApplicationMesh } = require("./procedural_application_mesh_common");

runApplicationMesh("watchtower_beacon")
  .then((payload) => {
    console.log("[procedural-watchtower-beacon-mesh-live] SUCCESS");
    console.log(JSON.stringify(payload, null, 2));
  })
  .catch((err) => {
    console.error("[procedural-watchtower-beacon-mesh-live] failed:", err && err.stack ? err.stack : err);
    process.exit(1);
  });
