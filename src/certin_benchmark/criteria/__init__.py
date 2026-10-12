"""Quality criteria Q1 to Q8 (Suite Section 6)."""

from . import q1, q2, q3, q4, q5, q6, q7, q8

CRITERIA = {"Q1": q1.evaluate, "Q2": q2.evaluate, "Q3": q3.evaluate, "Q4": q4.evaluate,
            "Q5": q5.evaluate, "Q6": q6.evaluate, "Q7": q7.evaluate, "Q8": q8.evaluate}
