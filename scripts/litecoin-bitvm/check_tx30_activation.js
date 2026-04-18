const path = require("path");

const tradelayerRepo = process.env.TRADELAYER_REPO || "C:\\projects\\tradelayer.js";
const Activation = require(path.join(tradelayerRepo, "src", "activation.js"));

async function main() {
  const activation = Activation.getInstance();
  await activation.init();
  const tx30Active = await activation.isTxTypeActive(30);
  process.stdout.write(
    JSON.stringify(
      {
        tx30Active,
        admin: activation.getAdmin(),
      },
      null,
      2
    ) + "\n"
  );
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
