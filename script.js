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

function createExpense(name, amount, category) {
  return {
    id: crypto.randomUUID(),
    name,
    amount: Number(amount),
    category,
    createdAt: new Date().toISOString()
  };
}

function validateExpense(name, amount) {
  if (!name.trim()) {
    return "Enter an expense name.";
  }

  if (!amount || Number(amount) <= 0) {
    return "Enter an amount greater than zero.";
  }

  return "";
}

function renderExpenses() {
  expenseList.innerHTML = "";

  expenses.forEach((expense) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${expense.name}</td>
      <td>${expense.category}</td>
      <td>${formatCurrency(expense.amount)}</td>
      <td><button class="delete-btn" type="button" data-id="${expense.id}">Delete</button></td>
    `;
    expenseList.append(row);
  });

  emptyState.hidden = expenses.length > 0;
  totalAmount.textContent = formatCurrency(
    expenses.reduce((sum, expense) => sum + expense.amount, 0)
  );
}

expenseForm.addEventListener("submit", (event) => {
  event.preventDefault();

  const error = validateExpense(expenseName.value, expenseAmount.value);
  formError.textContent = error;

  if (error) {
    return;
  }

  expenses.push(createExpense(
    expenseName.value.trim(),
    expenseAmount.value,
    expenseCategory.value
  ));

  expenseForm.reset();
  expenseName.focus();
  renderExpenses();
});

categoryFilter.addEventListener("change", renderExpenses);

renderExpenses();