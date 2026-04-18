const path = require("path");

const tradelayerRepo = process.env.TRADELAYER_REPO || "C:\\projects\\tradelayer.js";

require(path.join(tradelayerRepo, "tests", "utxoBitvmShortEpochRouterLive.js"));
