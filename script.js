const expenseForm = document.querySelector("#expenseForm");
const expenseName = document.querySelector("#expenseName");
const expenseAmount = document.querySelector("#expenseAmount");
const expenseCategory = document.querySelector("#expenseCategory");
const categoryFilter = document.querySelector("#categoryFilter");
const expenseList = document.querySelector("#expenseList");
const totalAmount = document.querySelector("#totalAmount");
const emptyState = document.querySelector("#emptyState");
const formError = document.querySelector("#formError");

let expenses = [];

function formatCurrency(value) {
  return `₹${Number(value).toLocaleString("en-IN")}`;
}

function renderExpenses() {
  expenseList.innerHTML = "";
  totalAmount.textContent = formatCurrency(0);
  emptyState.hidden = false;
}

expenseForm.addEventListener("submit", (event) => {
  event.preventDefault();
  renderExpenses();
});

categoryFilter.addEventListener("change", renderExpenses);

renderExpenses();