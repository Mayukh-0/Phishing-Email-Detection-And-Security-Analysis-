from flask import Flask, render_template, request
from detector import analyze_email

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    form_data = {"sender": "", "subject": "", "body": ""}

    if request.method == "POST":
        form_data = {
            "sender": request.form.get("sender", "").strip(),
            "subject": request.form.get("subject", "").strip(),
            "body": request.form.get("body", "").strip(),
        }
        if not all(form_data.values()):
            result = {"error": "Please fill in all three fields."}
        else:
            result = analyze_email(
                form_data["sender"], form_data["subject"], form_data["body"]
            )

    return render_template("index.html", result=result, form_data=form_data)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
