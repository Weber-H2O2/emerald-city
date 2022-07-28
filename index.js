const thsig = require("./pkg");


var items = [
  {idx: 0, save_path: "key.store"},
  {idx: 1, save_path: "key1.store"},
  {idx: 2, save_path: "key2.store"},
];
var results = [];

async function run(m, arg, callback) {
  console.log('参数为 ' + arg.idx + ":" + arg.save_path +' , 开始执行');

  await m.gg18_keygen(arg.idx, 3, arg.save_path)
}

function final(value) {
  console.log('完成: ', value);
}

thsig.then(m => {
  items.forEach(async function(item) {
    await run(m, item, function(result){
      results.push(result);
      if(results.length === items.length) {
        final(results[results.length - 1]);
      }
    })
  });
})
