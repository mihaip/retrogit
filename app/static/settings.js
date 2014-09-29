function updateWeeklyDayContainer() {
  var frequencyNode = document.getElementById("frequency");
  var weeklyDayContainerNode = document.getElementById("weekly-day-container");
  if (frequencyNode.value == "weekly") {
    weeklyDayContainerNode.style.display = "inline";
  } else {
    weeklyDayContainerNode.style.display = "none";
  }
}

function updateReposContainer() {
  var includedReposNode = document.getElementById("included-repos");
  var reposContainerNode = document.getElementById("repos-container");
  if (includedReposNode.value == "some") {
    reposContainerNode.style.display = "block";
  } else {
    var repoCheckboxes = document.querySelectorAll(".repo input[type=checkbox]");
    for (var i = 0; i < repoCheckboxes.length; i++) {
      repoCheckboxes[i].checked = true;
    }
    reposContainerNode.style.display = "none";
  }
}
