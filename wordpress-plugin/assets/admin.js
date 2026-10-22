(function () {
  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('input[name="selected_ips[]"]').forEach(function (input) {
      input.addEventListener('change', function () {
        if (document.querySelectorAll('input[name="selected_ips[]"]:checked').length > 50) {
          input.checked = false;
        }
      });
    });
  });
})();
