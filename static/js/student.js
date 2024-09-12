document
  .getElementById("profileForm")
  .addEventListener("submit", function (event) {
    event.preventDefault();

    const fullName = document.getElementById("fullName").value;
    const email = document.getElementById("email").value;
    const bio = document.getElementById("bio").value;

    console.log("Profile updated:");
    console.log("Full Name:", fullName);
    console.log("Email:", email);
    console.log("Bio:", bio);

    // Here you can add an AJAX request to send the updated data to the server

    alert("Your profile has been updated successfully!");
  });
