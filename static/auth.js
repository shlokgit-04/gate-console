// Shared auth page logic for Gate Console (login / register).
(function(){
  var mode = document.currentScript.dataset.mode;
  var form = document.getElementById(mode === 'login' ? 'loginform' : 'regform');
  var err = document.getElementById('err');
  form.addEventListener('submit', function(e){
    e.preventDefault();
    err.textContent = '';
    var email = document.getElementById('email').value.trim();
    var password = document.getElementById('password').value;
    fetch('/api/auth/' + mode, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email: email, password: password})
    }).then(function(r){ return r.json().then(function(j){ return {ok: r.ok, j: j}; }); })
    .then(function(res){
      if (res.ok) {
        localStorage.setItem('gc_token', res.j.token);
        window.location.href = '/';
      } else if (res.j.error === 'email_taken') {
        err.textContent = 'That email already has an account. Sign in instead.';
      } else if (res.j.error === 'invalid_credentials') {
        err.textContent = 'Wrong email or password.';
      } else if (res.j.error === 'rate_limited') {
        err.textContent = 'Too many attempts. Try again in a few minutes.';
      } else if (res.j.error === 'weak_password') {
        err.textContent = 'Password must be at least 8 characters.';
      } else {
        err.textContent = 'Something went wrong. Try again.';
      }
    })
    .catch(function(){ err.textContent = 'Network error. Try again.'; });
  });
})();
