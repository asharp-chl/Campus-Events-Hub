// Additional JavaScript functionality can be added here
// Most of the JavaScript is already included in the HTML templates

// Function to format date for display
function formatDate(dateString) {
    const options = { year: 'numeric', month: 'long', day: 'numeric' };
    return new Date(dateString).toLocaleDateString(undefined, options);
}

// Function to handle form submissions
document.addEventListener('DOMContentLoaded', function() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const submitButton = form.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.textContent = 'Processing...';
            }
        });
    });
});

// Function to check if user is logged in
function checkAuth() {
    return fetch('/api/check_auth')
        .then(response => response.json())
        .then(data => data.authenticated)
        .catch(error => false);
}
