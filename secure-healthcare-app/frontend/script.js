const users = [
    {
      email: "john@example.com",
      password: "john123",
      report: "Blood Pressure: 120/80\nCholesterol: Normal\nLast Visit: 2024-12-01"
    },
    {
      email: "jay@example.com",
      password: "jay456",
      report: "Blood Sugar: 90 mg/dL\nMRI: Normal\nNext Appointment: 2025-01-10"
    }
  ];
  
  function login() {
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value.trim();
    const error = document.getElementById("errorMsg");
  
    const user = users.find(u => u.email === email && u.password === password);
  
    if (user) {
      localStorage.setItem("report", user.report);
      window.location.href = "dashboard.html";
    } else {
      error.textContent = "Invalid email or password.";
    }
  }
