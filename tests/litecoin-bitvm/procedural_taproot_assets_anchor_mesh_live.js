const { runApplicationMesh } = require("./procedural_application_mesh_common");

runApplicationMesh("taproot_assets_anchor")
  .then((summary) => {
    console.log("[procedural-taproot-assets-anchor-mesh-live] SUCCESS");
    console.log(JSON.stringify(summary, null, 2));
  })
  .catch((err) => {
    console.error("[procedural-taproot-assets-anchor-mesh-live] failed:", err && err.stack ? err.stack : err);
    process.exit(1);
  });
