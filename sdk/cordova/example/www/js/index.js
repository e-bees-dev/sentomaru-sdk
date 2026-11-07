// after deviceready the plugin has clobbered window.Sentomaru; the button runs the flow on it.
'use strict';
document.addEventListener('deviceready', function () {
  var out = document.getElementById('log');
  document.getElementById('run').addEventListener('click', function () {
    window.runSentomaruFlow(window.Sentomaru, function (line) {
      var li = document.createElement('li');
      li.textContent = line;
      out.appendChild(li);
    });
  });
}, false);
