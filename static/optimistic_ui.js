// static/optimistic_ui.js

(function() {
    'use strict';

    function showPopup(message, isError = true) {
        const existingPopup = document.querySelector('.optimistic-popup');
        if (existingPopup) {
            document.body.removeChild(existingPopup);
        }

        const popup = document.createElement('div');
        popup.className = `optimistic-popup ${isError ? 'error' : 'success'}`;
        popup.textContent = message;

        const closeButton = document.createElement('button');
        closeButton.textContent = 'Dismiss';
        closeButton.onclick = () => {
            if (document.body.contains(popup)) {
                document.body.removeChild(popup);
            }
        };

        popup.appendChild(closeButton);
        document.body.appendChild(popup);

        // Automatically remove the popup after some time, especially for success messages
        if (!isError) {
            setTimeout(() => {
                if (document.body.contains(popup)) {
                    document.body.removeChild(popup);
                }
            }, 5000); // 5 seconds
        }
    }

    function handleFormSubmit(form, isAuthForm = false) {
        form.addEventListener('submit', function(event) {
            event.preventDefault();

            const submitButton = form.querySelector('button[type="submit"]');
            const originalButtonText = submitButton.textContent;
            submitButton.classList.add('is-loading');
            submitButton.disabled = true;

            const formData = new FormData(form);
            const action = form.getAttribute('action');
            const method = form.getAttribute('method');

            fetch(action, {
                method: method,
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => response.json().then(data => ({ ok: response.ok, status: response.status, data })))
            .then(({ ok, status, data }) => {
                if (ok) {
                    if (form.getAttribute('action') === '/signup') {
                        showPopup("Account created, please sign in.", false); // Show green success popup
                        form.reset();
                    } else if (isAuthForm && data.next_view !== undefined) {
                        window.location.href = data.next_view === '' ? '/' : `/${data.next_view}`;
                    } else {
                        form.reset();
                    }
                } else {
                    showPopup(data.error || "An unexpected error occurred. Please try again.");
                }
            })
            .catch(error => {
                console.error('Fetch Error:', error);
                showPopup("We couldn't connect to the server. Please check your internet connection.");
            })
            .finally(() => {
                submitButton.classList.remove('is-loading');
                submitButton.textContent = originalButtonText;
                submitButton.disabled = false;
            });
        });
    }

    document.addEventListener('DOMContentLoaded', function() {
        const loginForm = document.querySelector('form[action="/login"]');
        if (loginForm) {
            handleFormSubmit(loginForm, true);
        }

        const signupForm = document.querySelector('form[action="/signup"]');
        if (signupForm) {
            handleFormSubmit(signupForm, true);
        }

        const feedbackForm = document.querySelector('form[action="/submit_feedback"]');
        if (feedbackForm) {
            handleFormSubmit(feedbackForm);
        }
    });

})();
