function calc(i) {
	console.log(i);
	const expressionDiv = document.querySelector("#main > div");
	const expression = expressionDiv.textContent.trim();
	const result = eval(expression);
	const rounded = Math.floor(result);
	document.getElementById("response").value = rounded;
	respond()
	if (i >= 98) {
	  return;
	}
	setTimeout(() => {
	  calc(i + 1);
	}, 50);
}

calc(0);

