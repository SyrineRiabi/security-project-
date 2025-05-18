# === Imports ===
from flask import Flask, render_template, request         # Flask for web handling
from password_checker import check_password_strength      # Your backend password logic
from models import SessionLocal, PasswordResult  # 🔄 SQLAlchemy session + model

# === Initialize Flask App ===
app = Flask(__name__)

# === Main Route ===
# Define the route for the homepage. It accepts both GET (default page load) and POST (form submission) methods.
@app.route("/", methods=["GET", "POST"])
def index():
    feedback = None     # Variable to hold the feedback message from password analysis
    strength = None     # Variable to store a label for password strength (strong/moderate/weak)

    # If the user submitted the form (POST request)
    if request.method == "POST":
        # Get data entered in the form by the user
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        # Run the custom password analysis logic (defined in password_checker.py)
        feedback = check_password_strength(username, password, email=email)
        # Split feedback into lines
        lines = feedback.split("\n")

        # Remove the first line (emoji + label), and last two lines (entropy + crack time)
        if len(lines) >= 4:
            core_feedback_lines = lines[1:-2]  # everything between first and last two lines
        else:
            core_feedback_lines = lines[1:]  # fallback in case something changes
        
    
        # Join the useful part as a single string
        core_feedback = "\n".join(core_feedback_lines).strip()
    

        # Try to extract entropy from the feedback string
        entropy_line = next((line for line in feedback.split("\n") if "Entropy" in line), None)
        entropy = float(entropy_line.split(":")[1].strip().split()[0]) if entropy_line else 0

        # Try to extract estimated crack time from the feedback string
        crack_time_line = next((line for line in feedback.split("\n") if "crack time" in line), None)
        crack_time = crack_time_line.split(":")[1].strip() if crack_time_line else "Unknown"

        # Detect the general strength label based on feedback emoji
        if feedback.startswith("✅"):
            strength = "strong"
        elif feedback.startswith("⚠️"):
            strength = "moderate"
        else:
            strength = "weak"

        # Save the result into the database using SQLAlchemy ORM
        try:
            db = SessionLocal()  # Open a new database session
            result = PasswordResult(  # Create a new entry using your ORM model
                username=username,
                email=email,
                entropy=entropy,
                crack_time=crack_time,
                strength=strength,
                feedback=core_feedback   # 🆕 Store the full string returned by check_password_strength
            )
            db.add(result)     # Add the record to the session
            db.commit()        # Commit the transaction (save it to the DB)
            db.close()         # Close the session to free up resources
        except Exception as e:
            print("❌ SQLAlchemy error:", e)  # Print the error if something goes wrong

    # Render the HTML template and pass feedback + strength to it
    return render_template("index.html", feedback=feedback, strength=strength)


@app.route("/results")
def results():
    # 🧠 On ouvre une session vers la base de données
    db = SessionLocal()

    try:
        # 🔄 On récupère tous les résultats classés du plus récent au plus ancien
        records = db.query(PasswordResult).order_by(PasswordResult.submitted_at.desc()).all()

        # ✅ On ferme proprement la session après lecture
        db.close()

        # 🎯 On passe les résultats à la page HTML results.html
        return render_template("results.html", records=records)

    except Exception as e:
        # ⚠️ En cas d'erreur, on renvoie le message (debug temporaire)
        return f"Database error: {e}"
# === Run the App ===
# This block ensures that the Flask app only runs when this file is executed directly.
if __name__ == "__main__":
    print("🚀 Flask app starting...")  # Helpful startup message
    app.run(debug=True)  # Launch the Flask dev server with debugging enabled