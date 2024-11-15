// Password visibility toggle
        document.getElementById('togglePassword').addEventListener('click', function () {
            const passwordInput = document.getElementById('password');
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            this.textContent = type === 'password' ? '👁' : '🙈'; // Change icon based on visibility
        });

        // Client-side validation and form submission
        document.getElementById('loginForm').addEventListener('submit', function(event) {
            event.preventDefault();
            document.getElementById('emailError').textContent = '';
            document.getElementById('passwordError').textContent = '';
            document.getElementById('formError').textContent = '';

            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value.trim();
            let hasError = false;

            const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailPattern.test(email)) {
                document.getElementById('emailError').textContent = 'Please enter a valid email address.';
                hasError = true;
            }

            if (password.length < 8) {
                document.getElementById('passwordError').textContent = 'Password must be at least 8 characters long.';
                hasError = true;
            }

            if (hasError) {
                return; // Stop submission if there are errors
            }

            fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email, password: password }),
                credentials: 'include' // Include credentials for session cookies
            })
            .then(response => {
                return response.json().then(data => {
                    if (!response.ok) {
                        throw new Error(data.message || 'Login failed.');
                    }
                    return data;
                });
            })
            .then(data => {
                if (data.success) {
                    window.location.href = '/dashboard.html'; // Redirect to dashboard
                } else {
                    document.getElementById('formError').textContent = data.message;
                }
            })
            .catch(error => {
                console.error('Error during login:', error);
                document.getElementById('formError').textContent = error.message || 'An error occurred during login.';
            });
        });