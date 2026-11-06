
const fileInput = document.getElementById("email_file");
const fileName = document.getElementById("file-name");

if (fileInput && fileName) {
  fileInput.addEventListener("change", () => {
    const file = fileInput.files && fileInput.files[0];
    fileName.textContent = file ? file.name : "Choose an .eml file";

    if (file && file.size > 1024 * 1024) {
      alert("This file exceeds the 1 MB limit.");
      fileInput.value = "";
      fileName.textContent = "Choose an .eml file";
    }
  });
}

const downloadButton = document.getElementById("download-report");
const reportElement = document.getElementById("report-data");

if (downloadButton && reportElement) {
  downloadButton.addEventListener("click", () => {
    try {
      const report = JSON.parse(reportElement.textContent);
      const blob = new Blob(
        [JSON.stringify(report, null, 2)],
        { type: "application/json" }
      );

      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "phishlens-report.json";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch {
      alert("Unable to export this report. Please run the analysis again.");
    }
  });
}

