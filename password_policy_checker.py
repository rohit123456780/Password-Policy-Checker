import tkinter as tk
import string

class PasswordPolicyChecker:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Policy Compliance Checker")

        # Admin panel to define password policies
        self.policy_frame = tk.LabelFrame(master, text="Define Password Policy")
        self.policy_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        self.min_length_label = tk.Label(self.policy_frame, text="Minimum Length:")
        self.min_length_label.grid(row=0, column=0, padx=5, pady=5)
        self.min_length_entry = tk.Entry(self.policy_frame, width=5)
        self.min_length_entry.grid(row=0, column=1, padx=5, pady=5)

        self.include_upper = tk.BooleanVar()
        self.include_lower = tk.BooleanVar()
        self.include_digits = tk.BooleanVar()
        self.include_special = tk.BooleanVar()

        self.upper_check = tk.Checkbutton(self.policy_frame, text="Require Uppercase (A-Z)", variable=self.include_upper)
        self.upper_check.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        self.lower_check = tk.Checkbutton(self.policy_frame, text="Require Lowercase (a-z)", variable=self.include_lower)
        self.lower_check.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        self.digits_check = tk.Checkbutton(self.policy_frame, text="Require Digits (0-9)", variable=self.include_digits)
        self.digits_check.grid(row=3, column=0, columnspan=2, padx=5, pady=5)
        self.special_check = tk.Checkbutton(self.policy_frame, text="Require Special Characters (!@#...)", variable=self.include_special)
        self.special_check.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

        # User panel to check password compliance
        self.user_frame = tk.LabelFrame(master, text="Check Password Compliance")
        self.user_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        self.password_label = tk.Label(self.user_frame, text="Enter Password:")
        self.password_label.grid(row=0, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(self.user_frame, show='*', width=30)
        self.password_entry.grid(row=0, column=1, padx=5, pady=5)

        self.check_button = tk.Button(self.user_frame, text="Check Compliance", command=self.check_compliance)
        self.check_button.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        self.result_label = tk.Label(self.user_frame, text="", fg="blue")
        self.result_label.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

    def check_compliance(self):
        password = self.password_entry.get()
        min_length = int(self.min_length_entry.get()) if self.min_length_entry.get() else 0
        policy_requirements = {
            'min_length': min_length,
            'require_upper': self.include_upper.get(),
            'require_lower': self.include_lower.get(),
            'require_digits': self.include_digits.get(),
            'require_special': self.include_special.get()
        }

        compliance, feedback = self.evaluate_password(password, policy_requirements)
        self.result_label.config(text=feedback, fg="green" if compliance else "red")

    def evaluate_password(self, password, policy):
        feedback = []
        compliance = True

        if len(password) < policy['min_length']:
            feedback.append(f"Password must be at least {policy['min_length']} characters long.")
            compliance = False

        if policy['require_upper'] and not any(c.isupper() for c in password):
            feedback.append("Password must include at least one uppercase letter.")
            compliance = False

        if policy['require_lower'] and not any(c.islower() for c in password):
            feedback.append("Password must include at least one lowercase letter.")
            compliance = False

        if policy['require_digits'] and not any(c.isdigit() for c in password):
            feedback.append("Password must include at least one digit.")
            compliance = False

        if policy['require_special'] and not any(c in string.punctuation for c in password):
            feedback.append("Password must include at least one special character.")
            compliance = False

        if compliance:
            feedback = ["Password complies with the policy."]
        return compliance, "\n".join(feedback)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordPolicyChecker(root)
    root.mainloop()
