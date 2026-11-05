"""Explain the strongest positive TF-IDF contributions for Logistic Regression."""
def explain_prediction(model, message, top_n=6):
    vectorizer = model.named_steps["tfidf"]
    classifier = model.named_steps["classifier"]
    classes = list(classifier.classes_)
    if "phishing" not in classes:
        return []
    phishing_index = classes.index("phishing")
    vector = vectorizer.transform([message])
    coefficients = classifier.coef_[0]
    if phishing_index == 0:
        coefficients = -coefficients
    contributions = vector.multiply(coefficients).toarray().ravel()
    names = vectorizer.get_feature_names_out()
    indices = contributions.argsort()[::-1]
    result = []
    for idx in indices:
        if contributions[idx] <= 0:
            break
        result.append({
            "term": str(names[idx]),
            "contribution": round(float(contributions[idx]), 4)
        })
        if len(result) >= top_n:
            break
    return result
