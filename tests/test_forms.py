from __future__ import annotations

from atlasscan.core.crawler import Form
from atlasscan.modules.forms import _benign


def test_wordpress_postpass_is_benign():
    form = Form("https://example.test/wp-login.php?action=postpass", "POST", ["post_password"])
    assert _benign(form)


def test_post_password_field_alone_is_benign():
    assert _benign(Form("https://example.test/protected", "POST", ["post_password"]))


def test_wordpress_comment_form_is_benign():
    form = Form("https://example.test/wp-comments-post.php", "POST", ["comment", "author"])
    assert _benign(form)


def test_search_form_is_benign():
    assert _benign(Form("https://example.test/search", "POST", ["q"]))
    assert _benign(Form("https://example.test/", "POST", ["s", "search"]))


def test_real_login_form_is_not_benign():
    assert not _benign(Form("https://example.test/login", "POST", ["user", "pass"]))
    assert not _benign(Form("https://example.test/wp-login.php", "POST", ["log", "pwd"]))
