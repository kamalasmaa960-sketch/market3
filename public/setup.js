const form = document.getElementById("setupForm");
const result = document.getElementById("setupResult");
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submit = form.querySelector('button[type="submit"]');
  submit.disabled = true;
  result.textContent = "جارٍ إنشاء الحساب...";
  const payload = Object.fromEntries(new FormData(form));
  try {
    const response = await fetch("/api/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `فشل الطلب (${response.status})`);
    form.reset();
    form.hidden = true;
    result.textContent = "تم إنشاء حساب المدير. انتقلي إلى صفحة الإدارة وسجّلي الدخول.";
  } catch (error) {
    result.textContent = error.message || "تعذر الاتصال بالخادم. تأكدي من نجاح النشر وإعداد D1.";
  } finally {
    submit.disabled = false;
  }
});
