const query = new URLSearchParams(location.search).get("q");
document.querySelector("#output").innerHTML = query;
