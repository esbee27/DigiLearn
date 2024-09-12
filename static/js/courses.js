document
  .getElementById("feedbackForm")
  .addEventListener("submit", function (event) {
    event.preventDefault();

    const feedback = document.getElementById("feedback").value;

    console.log("Feedback submitted:", feedback);

    // Placeholder for AJAX request to send feedback to the server

    alert("Thank you for your feedback!");
  });
