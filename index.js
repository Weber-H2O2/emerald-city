const thsig = require("./pkg");

var items = [
  { idx: 0, save_path: "key1.store" },
  { idx: 1, save_path: "key2.store" },
  { idx: 2, save_path: "key3.store" },
];
var results = [];

let t = 1;
let n = 3;

async function keygen(m, arg) {
  return await m.gg18_keygen(t, n, arg.save_path);
}

async function sign(m, arg, key_store) {
  return await m.gg18_sign(t, n, key_store, "Hello Eigen");
}

thsig.then((m) => {
  items.forEach(async function (item) {
    res = await keygen(m, item);
    // console.log(item.idx, " ", res);
    results.push(res);

    if (results.length == items.length) {
      console.log(results.length);
      items.forEach(async function (item) {
        if (item.idx < t + 1) {
          console.log(item.idx, " ", results[item.idx]);
          res = await sign(m, item, results[item.idx]);
          console.log("Sign result: ", res);
        }
      });
    }
  });
});
