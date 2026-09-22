const expenseForm = document.querySelector("#expenseForm");
const expenseName = document.querySelector("#expenseName");
const expenseAmount = document.querySelector("#expenseAmount");
const expenseCategory = document.querySelector("#expenseCategory");
const categoryFilter = document.querySelector("#categoryFilter");
const expenseList = document.querySelector("#expenseList");
const totalAmount = document.querySelector("#totalAmount");
const emptyState = document.querySelector("#emptyState");
const formError = document.querySelector("#formError");

const STORAGE_KEY = "code-cameo-expenses";
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

function saveExpenses() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(expenses));
}

function loadExpenses() {
  const savedExpenses = localStorage.getItem(STORAGE_KEY);

  if (!savedExpenses) {
    return [];
  }

  try {
    return JSON.parse(savedExpenses);
  } catch {
    localStorage.removeItem(STORAGE_KEY);
    return [];
  }
}

function getVisibleExpenses() {
  if (categoryFilter.value === "All") {
    return expenses;
  }

  return expenses.filter((expense) => expense.category === categoryFilter.value);
}

function renderExpenses() {
  const visibleExpenses = getVisibleExpenses();

  expenseList.innerHTML = "";

  visibleExpenses.forEach((expense) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${expense.name}</td>
      <td>${expense.category}</td>
      <td>${formatCurrency(expense.amount)}</td>
      <td><button class="delete-btn" type="button" data-id="${expense.id}">Delete</button></td>
    `;
    expenseList.append(row);
  });

  emptyState.textContent = expenses.length === 0
    ? "No expenses yet. Add your first one."
    : "No expenses match this filter.";
  emptyState.hidden = visibleExpenses.length > 0;
  totalAmount.textContent = formatCurrency(
    visibleExpenses.reduce((sum, expense) => sum + expense.amount, 0)
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

  saveExpenses();
  expenseForm.reset();
  expenseName.focus();
  renderExpenses();
});

expenseList.addEventListener("click", (event) => {
  if (!event.target.matches(".delete-btn")) {
    return;
  }

  expenses = expenses.filter((expense) => expense.id !== event.target.dataset.id);
  saveExpenses();
  renderExpenses();
});

categoryFilter.addEventListener("change", renderExpenses);

expenses = loadExpenses();
renderExpenses();