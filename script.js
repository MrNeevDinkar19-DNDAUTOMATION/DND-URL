
const API_URL = "http://127.0.0.1:8000/scan";

const scanForm = document.getElementById("scanForm");
const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");
const result = document.getElementById("result");
const resultTitle = document.getElementById("resultTitle");

function showResult(title, level = "unknown") {
    result.className = `result ${String(level).toLowerCase()}`;

    resultTitle.replaceChildren();
    resultTitle.hidden = false;
    resultTitle.textContent = title;
}

function showError(title) {
    result.className = "result error";

    resultTitle.replaceChildren();
    resultTitle.hidden = false;
    resultTitle.textContent = title;
}

scanForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const url = urlInput.value.trim();

    if (!url) {
        showError("Enter a URL");
        return;
    }

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";

    resultTitle.hidden = false;
    resultTitle.textContent = "Scanning...";
    result.className = "result loading";

    try {
        const response = await fetch(API_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url })
        });

        let data;

        try {
            data = await response.json();
        } catch {
            throw new Error("The backend returned an invalid response.");
        }

        if (!response.ok) {
            throw new Error(
                typeof data.detail === "string"
                    ? data.detail
                    : "Please check the URL and try again."
            );
        }

        const level = String(
            data.risk_level || "unknown"
        ).toLowerCase();

        let title = "URL analysis completed";

        if (level === "high") {
            title = "High risk — suspicious URL.";
        } else if (level === "medium") {
            title = "Caution — potential risk detected.";
        } else if (level === "low") {
            title = "Low risk indicators detected.";
        }

        showResult(title, level);

    } catch (error) {
        console.error("URL Guard scan failed:", error);

        if (error.message.includes("Failed to fetch")) {
            showError("Connection failed — start the FastAPI backend.");
        } else if (
            error.message === "The backend returned an invalid response."
        ) {
            showError("Invalid backend response");
        } else {
            showError("Unable to scan URL");
        }

    } finally {
        scanButton.disabled = false;
        scanButton.textContent = "Scan URL";
    }
});
