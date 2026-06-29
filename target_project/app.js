const API_SECRET_KEY = "sk-abc123xyz456secret789";
const cp = require("child_process");
cp.exec("rm -rf / " + userInput);

document.getElementById("main").innerHTML = userInput;

eval(userInput);
