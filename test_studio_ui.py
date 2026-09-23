"""Playwright tests of DAgent Studio itself (spec §37, §48 "UI", §49).

Run from backend/: ``uv run pytest -q ../e2e`` (the browser tests need the built
frontend). The full Snake scenario is marked e2e and takes a few minutes.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import Page, expect, sync_playwright

REQUEST = "Create a Snake game using React. Make it playable, run it locally, test it in a real browser, and fix anything that does not work."


def _open(url: str):
    playwright = sync_playwright().start()
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context(viewport={"width": 1440, "height": 900})
    page = context.new_page()
    page.goto(url, wait_until="load")
    return playwright, browser, page


@pytest.fixture
def page(studio_url):
    playwright, browser, page = _open(studio_url)
    yield page
    browser.close()
    playwright.stop()


@pytest.fixture
def fresh_page(fresh_studio_url):
    playwright, browser, page = _open(fresh_studio_url)
    yield page
    browser.close()
    playwright.stop()


def test_three_columns_and_header(page: Page):
    expect(page.get_by_test_id("column-files")).to_be_visible()
    expect(page.get_by_test_id("column-code")).to_be_visible()
    expect(page.get_by_test_id("column-agent")).to_be_visible()
    expect(page.get_by_text("DAgent Studio", exact=True)).to_be_visible()
    expect(page.get_by_test_id("version")).to_contain_text("v1.0")
    for phase in ("build", "test", "deploy", "autonomous"):
        expect(page.get_by_test_id(f"phase-{phase}")).to_be_visible()
    expect(page.get_by_test_id("connection")).to_have_attribute("data-state", "open", timeout=10000)
    expect(page.get_by_test_id("message-list")).to_be_visible()
    # No fake chat history.
    assert page.get_by_test_id("message-agent").count() == 0
    # The Agent column is a chatbot only: no tabs/dashboards.
    assert page.get_by_test_id("column-agent").get_by_role("tab").count() == 0


def test_theme_toggle_and_resizable_columns(page: Page):
    html = page.locator("html")
    expect(html).to_have_attribute("data-theme", "dark")
    page.get_by_test_id("theme-toggle").click()
    expect(html).to_have_attribute("data-theme", "light")
    page.get_by_test_id("theme-toggle").click()
    files = page.get_by_test_id("column-files")
    before = files.bounding_box()["width"]
    splitter = page.get_by_role("separator", name="Resize files panel")
    box = splitter.bounding_box()
    page.mouse.move(box["x"] + 2, box["y"] + 200)
    page.mouse.down()
    page.mouse.move(box["x"] + 60, box["y"] + 200, steps=5)
    page.mouse.up()
    after = files.bounding_box()["width"]
    assert after > before
    assert after <= 360


def test_conversation_and_knowledge(page: Page):
    composer = page.get_by_test_id("composer")
    composer.fill("hi")
    composer.press("Enter")
    expect(page.get_by_test_id("message-agent").last).to_contain_text("Hello", timeout=10000)
    composer.fill("what is Playwright?")
    composer.press("Enter")
    expect(page.get_by_test_id("message-agent").last).to_contain_text("Playwright is", timeout=10000)
    composer.fill("")
    expect(page.get_by_test_id("send")).to_be_disabled()


def test_workspace_picker_and_files(page: Page, tmp_path):
    (tmp_path / "hello.txt").write_text("hello studio")
    page.get_by_test_id("choose-folder").click()
    expect(page.get_by_test_id("workspace-picker")).to_be_visible()
    # Navigate the in-page browser to the temporary directory through real listings.
    parts = [p for p in str(tmp_path).split("/") if p]
    page.get_by_role("button", name="Go to home folder").click()
    current = page.get_by_test_id("picker-path")
    while current.inner_text() != "/":
        page.get_by_role("button", name="..").click()
        page.wait_for_timeout(100)
    for part in parts:
        page.get_by_test_id("picker-entries").get_by_role("button", name=part, exact=True).click()
        expect(current).to_contain_text(part)
    page.get_by_test_id("picker-use").click()
    expect(page.get_by_test_id("workspace-picker")).to_be_hidden(timeout=10000)
    expect(page.get_by_test_id("workspace-name")).to_have_text(tmp_path.name)
    expect(page.get_by_test_id("file-tree")).to_contain_text("hello.txt")
    page.get_by_text("hello.txt").click()
    expect(page.get_by_test_id("breadcrumb")).to_contain_text("hello.txt")
    expect(page.get_by_test_id("editor-status")).to_contain_text("Saved")
    # Edit through Monaco and persist through the backend.
    page.locator(".monaco-editor textarea").focus()
    page.keyboard.press("End")
    page.keyboard.type(" edited")
    expect(page.get_by_test_id("save-state")).to_have_text("Unsaved changes")
    page.keyboard.press("Control+S")
    expect(page.get_by_test_id("save-state")).to_have_text("Saved", timeout=5000)
    assert (tmp_path / "hello.txt").read_text() == "hello studio edited"
    # Create a file from the Files column.
    page.get_by_test_id("new-file").click()
    page.get_by_test_id("create-input").fill("notes.md")
    page.get_by_test_id("create-input").press("Enter")
    expect(page.get_by_test_id("file-tree")).to_contain_text("notes.md", timeout=5000)
    assert (tmp_path / "notes.md").exists()


def _pick(page: Page, target) -> None:
    """Drive the in-page picker to a real directory through real listings."""
    expect(page.get_by_test_id("workspace-picker")).to_be_visible(timeout=15000)
    page.get_by_role("button", name="Go to home folder").click()
    current = page.get_by_test_id("picker-path")
    while current.inner_text() != "/":
        page.get_by_role("button", name="..").click()
        page.wait_for_timeout(100)
    for part in [p for p in str(target).split("/") if p]:
        page.get_by_test_id("picker-entries").get_by_role("button", name=part, exact=True).click()
        expect(current).to_contain_text(part)
    page.get_by_test_id("picker-use").click()
    expect(page.get_by_test_id("workspace-picker")).to_be_hidden(timeout=10000)


@pytest.mark.e2e
def test_snake_scenario_through_the_ui(fresh_page: Page, tmp_path):
    page = fresh_page
    workspace = tmp_path / "snake-workspace"
    workspace.mkdir()
    composer = page.get_by_test_id("composer")
    composer.fill(REQUEST)
    composer.press("Enter")
    page.wait_for_timeout(1500)
    if page.get_by_test_id("workspace-picker").count():
        _pick(page, workspace)
    # Real progress messages tied to real events.
    expect(page.get_by_test_id("message-status").filter(has_text="Installing dependencies")).to_be_visible(timeout=60000)
    expect(page.get_by_test_id("file-tree")).to_contain_text("package.json", timeout=60000)
    expect(page.get_by_test_id("message-status").filter(has_text="Testing in a real browser")).to_be_visible(timeout=300000)
    result = page.get_by_test_id("message-agent").filter(has=page.get_by_test_id("checklist"))
    expect(result).to_be_visible(timeout=600000)
    expect(result).to_contain_text("complete and verified")
    assert result.locator("[data-passed=false]").count() == 0
    link = result.get_by_test_id("open-in-browser")
    url = link.get_attribute("href")
    assert url and url.startswith("http://127.0.0.1:")
    # The Files column reflects the real generated project and the editor opens real files.
    expect(page.get_by_test_id("file-tree")).to_contain_text("package.json")
    page.get_by_test_id("file-search").fill("engine")
    expect(page.get_by_test_id("file-tree")).to_contain_text("engine.ts", timeout=5000)
    page.get_by_text("engine.ts", exact=True).first.click()
    expect(page.get_by_test_id("breadcrumb")).to_contain_text("engine.ts")
    expect(page.get_by_test_id("status-requirements")).to_contain_text("/")
    # The generated game really runs: open it in a second tab and play one move.
    game = page.context.new_page()
    game.goto(url)
    game.wait_for_selector("html[data-input-ready='true']")
    game.keyboard.press("ArrowRight")
    expect(game.get_by_test_id("board")).to_have_attribute("data-status", "playing", timeout=5000)
    game.close()


@pytest.mark.e2e
def test_portfolio_scenario_through_the_ui(fresh_page: Page, tmp_path):
    """The request that used to be refused, driven through the real UI."""
    page = fresh_page
    workspace = tmp_path / "portfolio-workspace"
    workspace.mkdir()
    composer = page.get_by_test_id("composer")
    composer.fill("create a best portfolio website")
    composer.press("Enter")

    # The agent states what it understood before asking for anything.
    understanding = page.get_by_test_id("message-agent").filter(has_text="Understood")
    expect(understanding).to_be_visible(timeout=20000)
    expect(understanding).to_contain_text("portfolio")
    expect(understanding).to_contain_text("high quality")
    assert "built-in composition" not in page.get_by_test_id("message-list").inner_text()

    _pick(page, workspace)
    expect(page.get_by_test_id("message-agent").filter(has_text="Stack chosen on the evidence")).to_be_visible(timeout=120000)
    expect(page.get_by_test_id("file-tree")).to_contain_text("package.json", timeout=120000)
    result = page.get_by_test_id("message-agent").filter(has=page.get_by_test_id("checklist"))
    expect(result).to_be_visible(timeout=900000)
    expect(result).to_contain_text("complete and verified")
    assert result.locator("[data-passed=false]").count() == 0

    url = result.get_by_test_id("open-in-browser").get_attribute("href")
    assert url and url.startswith("http://127.0.0.1:")
    site = page.context.new_page()
    site.goto(url)
    expect(site.get_by_test_id("hero-title")).to_be_visible()
    expect(site.get_by_test_id("projects")).to_be_visible()
    site.get_by_test_id("nav-link").first.click()
    expect(site.locator("main")).to_be_visible()
    site.close()
