function copyIdText(element_id) {
  var copyText = document.getElementById(element_id);
  copyText.select();
  document.execCommand("copy");
}
