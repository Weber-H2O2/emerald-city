const thsig = require("./pkg");

var items = [
  { idx: 0, save_path: "key.store" },
  { idx: 1, save_path: "key1.store" },
  { idx: 2, save_path: "key2.store" },
];
var results = [];

async function keygen(m, arg) {
  console.log("参数为 " + arg.idx + ":" + arg.save_path + " , 开始执行");

  return await m.gg18_keygen(arg.idx, 3, arg.save_path);
}

async function sign(m, arg, key_store) {
  return await m.gg18_sign(arg.idx, 3, key_store, "Hello Eigen");
}

function final(value) {
  console.log("完成: ", value);
}

thsig.then((m) => {
  items.forEach(async function (item) {
    res = await keygen(m, item);
    // console.log(item.idx, " ", res);
    results.push(res);

    if (results.length == items.length) {
      console.log(results.length);
      items.forEach(async function (item) {
        console.log(item.idx, " ", results[item.idx]);
        res = await sign(m, item, results[item.idx]);
      });
    }
  });
});
