const thsig = require("./pkg");

var items = [{ idx: 0 }, { idx: 1 }, { idx: 2 }];
var results = [];

let t = 1;
let n = 3;

async function keygen(m, arg) {
  return await m.gg18_keygen(t, n);
}

async function keygen_new_context(m, arg) {
  return await m.gg18_keygen_client_context(t, n);
}

async function keygen_client_round1(m, context) {
  return await m.gg18_keygen_client_round1(context);
}

async function sign(m, arg, key_store) {
  return await m.gg18_sign(t, n, key_store, "Hello Eigen");
}

thsig.then((m) => {
  items.forEach(async function (item) {
    context = await keygen_new_context(m);
    console.log(context);

    res = await keygen_client_round1(m, context);
    results.push(res);
    // if (results.length == items.length) {
    //   console.log(results.length);
    //   items.forEach(async function (item) {
    //     if (item.idx < t + 1) {
    //       console.log(item.idx, " ", results[item.idx]);
    //       res = await sign(m, item, results[item.idx]);
    //       console.log("Sign result: ", res);
    //     }
    //   });
    // }
  });
});
