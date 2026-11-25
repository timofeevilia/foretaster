"""The server-side deployment script, run against a local stand-in for GitHub."""

import functools
import http.server
import os
import shutil
import subprocess
import tarfile
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parent.parent / "site" / "deploy"
COMMIT_1 = "1" * 40
COMMIT_2 = "2" * 40
HTACCESS = "AddType application/wasm .wasm\n"

pytestmark = pytest.mark.skipif(
    os.name != "posix" or any(shutil.which(tool) is None for tool in ("sh", "curl", "tar")),
    reason="needs a POSIX shell, curl and tar",
)


class Origin:
    """A directory served over HTTP that plays the part of the site-dist branch."""

    def __init__(self, root: Path, url: str) -> None:
        self.root = root
        self.url = url
        self.builds = 0

    def stage(self, files: dict[str, str], commit: str) -> Path:
        """Package ``files`` as a build and return its tree, not yet published."""
        self.builds += 1
        dist = self.root / f"dist-{self.builds}"
        for name, text in files.items():
            path = dist / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        tree = self.root / f"tree-{self.builds}"
        subprocess.run(  # noqa: S603 - fixed arguments
            ["sh", str(DEPLOY / "package.sh"), str(dist), str(tree), commit],  # noqa: S607
            check=True,
        )
        return tree

    def serve(self, tree: Path) -> None:
        with tarfile.open(self.root / "site.tar.gz", "w:gz") as archive:
            archive.add(tree, arcname="foretaster-site-dist")
        shutil.copy(tree / "VERSION", self.root / "VERSION")

    def publish(self, files: dict[str, str], commit: str) -> None:
        self.serve(self.stage(files, commit))


Pull = Callable[..., subprocess.CompletedProcess[str]]


@pytest.fixture
def origin(tmp_path: Path) -> Iterator[Origin]:
    root = tmp_path / "origin"
    root.mkdir()
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    handler.log_message = lambda *_: None  # type: ignore[attr-defined]
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield Origin(root, f"http://127.0.0.1:{server.server_address[1]}")
    server.shutdown()
    server.server_close()


@pytest.fixture
def target(tmp_path: Path) -> Path:
    path = tmp_path / "home" / "foretaster.example.org"
    path.mkdir(parents=True)
    return path


@pytest.fixture
def pull(tmp_path: Path, origin: Origin, target: Path) -> Pull:
    def run(directory: Path = target, **extra: str) -> subprocess.CompletedProcess[str]:
        environment = {
            "PATH": os.environ["PATH"],
            "HOME": str(tmp_path / "home"),
            "NO_PROXY": "127.0.0.1",
            "FORETASTER_VERSION_URL": f"{origin.url}/VERSION",
            "FORETASTER_ARCHIVE_URL": f"{origin.url}/site.tar.gz",
            "FORETASTER_TEST_ALLOW_HTTP": "1",
            **extra,
        }
        return subprocess.run(  # noqa: S603 - fixed arguments
            ["sh", str(DEPLOY / "pull.sh"), str(directory)],  # noqa: S607
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    return run


def site(**changes: str) -> dict[str, str]:
    files = {
        "index.html": "<title>Foretaster</title>",
        "app.js": "run()",
        "ru/index.html": "<title>Foretaster</title>",
        "pyodide/pyodide.asm.wasm": "wasm",
        ".htaccess": HTACCESS,
    }
    files.update(changes)
    return files


def state(target: Path, name: str) -> str:
    return (target.parent / ".foretaster-site" / name).read_text(encoding="utf-8")


def installed(target: Path) -> list[str]:
    return sorted(str(p.relative_to(target)) for p in target.rglob("*") if p.is_file())


def test_first_run_installs_the_site(origin: Origin, target: Path, pull: Pull) -> None:
    origin.publish(site(), COMMIT_1)
    result = pull()
    assert result.returncode == 0, result.stderr
    assert installed(target) == [
        ".htaccess",
        "app.js",
        "index.html",
        "pyodide/pyodide.asm.wasm",
        "ru/index.html",
    ]
    assert (target / "app.js").read_text(encoding="utf-8") == "run()"
    assert state(target, "version").strip() == COMMIT_1
    assert f"deployed {COMMIT_1}: 4 file(s) copied, 0 removed" in state(target, "log")
    assert not (target.parent / ".foretaster-site" / "lock").exists()


def test_nothing_is_downloaded_when_the_version_is_unchanged(
    origin: Origin, target: Path, pull: Pull
) -> None:
    origin.publish(site(), COMMIT_1)
    assert pull().returncode == 0
    (origin.root / "site.tar.gz").write_text("not an archive", encoding="utf-8")
    result = pull()
    assert result.returncode == 0, result.stderr
    assert state(target, "log").count("deployed") == 1


def test_update_changes_removes_and_leaves_foreign_files_alone(
    origin: Origin, target: Path, pull: Pull
) -> None:
    origin.publish(site(), COMMIT_1)
    assert pull().returncode == 0
    (target / ".well-known").mkdir()
    (target / ".well-known" / "token").write_text("host's own file", encoding="utf-8")
    (target / "notes.txt").write_text("mine", encoding="utf-8")

    files = site(**{"app.js": "run(2)", "pkg/new.whl": "wheel"})
    del files["ru/index.html"]
    origin.publish(files, COMMIT_2)
    result = pull()
    assert result.returncode == 0, result.stderr
    assert installed(target) == [
        ".htaccess",
        ".well-known/token",
        "app.js",
        "index.html",
        "notes.txt",
        "pkg/new.whl",
        "pyodide/pyodide.asm.wasm",
    ]
    assert not (target / "ru").exists()
    assert (target / "app.js").read_text(encoding="utf-8") == "run(2)"
    assert f"deployed {COMMIT_2}: 2 file(s) copied, 1 removed" in state(target, "log")


def test_a_file_changed_on_the_host_is_repaired_by_the_next_build(
    origin: Origin, target: Path, pull: Pull
) -> None:
    origin.publish(site(), COMMIT_1)
    assert pull().returncode == 0
    (target / "app.js").write_text("tampered", encoding="utf-8")
    origin.publish(site(), COMMIT_2)
    assert pull().returncode == 0
    assert (target / "app.js").read_text(encoding="utf-8") == "run()"


def test_a_changed_htaccess_is_kept_until_the_owner_removes_it(
    origin: Origin, target: Path, pull: Pull
) -> None:
    origin.publish(site(), COMMIT_1)
    assert pull().returncode == 0
    hostile = "AddType application/x-httpd-php .html\n"
    origin.publish(site(**{".htaccess": hostile}), COMMIT_2)
    assert pull().returncode == 0
    assert (target / ".htaccess").read_text(encoding="utf-8") == HTACCESS
    assert "ships a different .htaccess" in state(target, "log")

    (target / ".htaccess").unlink()
    assert pull().returncode == 0
    assert (target / ".htaccess").read_text(encoding="utf-8") == hostile


def refused(origin: Origin, target: Path, pull: Pull, message: str) -> None:
    """Deploy a good build, serve whatever the caller staged, and expect a refusal."""
    before = installed(target)
    result = pull()
    assert result.returncode == 1
    assert message in result.stderr
    assert message in state(target, "log")
    assert installed(target) == before
    assert state(target, "version").strip() == COMMIT_1
    assert (target / "app.js").read_text(encoding="utf-8") == "run()"


def test_a_file_that_does_not_match_its_checksum_is_refused(
    origin: Origin, target: Path, pull: Pull
) -> None:
    origin.publish(site(), COMMIT_1)
    assert pull().returncode == 0
    tree = origin.stage(site(**{"app.js": "run(2)"}), COMMIT_2)
    (tree / "site" / "app.js").write_text("steal()", encoding="utf-8")
    origin.serve(tree)
    refused(origin, target, pull, "does not match its checksum")


def test_a_file_missing_from_the_checksum_list_is_refused(
    origin: Origin, target: Path, pull: Pull
) -> None:
    origin.publish(site(), COMMIT_1)
    assert pull().returncode == 0
    tree = origin.stage(site(**{"app.js": "run(2)"}), COMMIT_2)
    (tree / "site" / "extra.js").write_text("steal()", encoding="utf-8")
    origin.serve(tree)
    refused(origin, target, pull, "do not match its checksum list")


@pytest.mark.parametrize(
    "name",
    ["shell.php", "cgi-bin/run.cgi", "ru/.htaccess", ".user.ini", "page.html.php", "noextension"],
)
def test_a_file_type_outside_the_allowlist_is_refused(
    origin: Origin, target: Path, pull: Pull, name: str
) -> None:
    origin.publish(site(), COMMIT_1)
    assert pull().returncode == 0
    origin.publish(site(**{"app.js": "run(2)", name: "x"}), COMMIT_2)
    refused(origin, target, pull, f"does not install: {name}")


def test_a_symbolic_link_in_the_archive_is_refused(
    origin: Origin, target: Path, pull: Pull
) -> None:
    origin.publish(site(), COMMIT_1)
    assert pull().returncode == 0
    tree = origin.stage(site(**{"app.js": "run(2)"}), COMMIT_2)
    (tree / "site" / "passwd.txt").symlink_to("/etc/passwd")
    origin.serve(tree)
    refused(origin, target, pull, "not a plain file")


def test_a_checksum_list_that_points_outside_the_site_is_refused(
    origin: Origin, target: Path, pull: Pull
) -> None:
    origin.publish(site(), COMMIT_1)
    assert pull().returncode == 0
    tree = origin.stage(site(**{"app.js": "run(2)"}), COMMIT_2)
    with (tree / "SHA256SUMS").open("a", encoding="utf-8") as manifest:
        manifest.write(f"{'0' * 64}  ./../escape.html\n")
    origin.serve(tree)
    refused(origin, target, pull, "does not install: ../escape.html")


def test_a_version_marker_that_is_not_a_commit_is_refused(
    origin: Origin, target: Path, pull: Pull
) -> None:
    origin.publish(site(), COMMIT_1)
    assert pull().returncode == 0
    (origin.root / "VERSION").write_text("$(rm -rf ~)\n", encoding="utf-8")
    refused(origin, target, pull, "is not a commit id")


@pytest.mark.parametrize(
    ("name", "text"), [("index.php", "<?php"), ("index.html", "<title>My shop</title>")]
)
def test_a_directory_with_another_site_is_refused(
    origin: Origin, target: Path, pull: Pull, name: str, text: str
) -> None:
    (target / name).write_text(text, encoding="utf-8")
    origin.publish(site(), COMMIT_1)
    result = pull()
    assert result.returncode == 1
    assert "refusing to deploy there" in result.stderr
    assert installed(target) == [name]


def test_a_manually_uploaded_copy_of_the_site_is_taken_over(
    origin: Origin, target: Path, pull: Pull
) -> None:
    (target / "index.html").write_text("<title>Foretaster</title> old", encoding="utf-8")
    origin.publish(site(), COMMIT_1)
    assert pull().returncode == 0
    assert (target / "index.html").read_text(encoding="utf-8") == "<title>Foretaster</title>"


def test_state_is_tied_to_one_directory(origin: Origin, target: Path, pull: Pull) -> None:
    origin.publish(site(), COMMIT_1)
    assert pull().returncode == 0
    other = target.parent / "other"
    other.mkdir()
    result = pull(other)
    assert result.returncode == 1
    assert "belongs to" in result.stderr
    assert installed(other) == []


def test_plain_http_is_refused_outside_tests(origin: Origin, target: Path, pull: Pull) -> None:
    origin.publish(site(), COMMIT_1)
    result = pull(FORETASTER_TEST_ALLOW_HTTP="0")
    assert result.returncode == 1
    assert "not HTTPS" in result.stderr
    assert installed(target) == []


def test_a_run_in_progress_makes_a_second_run_step_aside(
    origin: Origin, target: Path, pull: Pull
) -> None:
    origin.publish(site(), COMMIT_1)
    lock = target.parent / ".foretaster-site" / "lock"
    lock.mkdir(parents=True)
    result = pull()
    assert result.returncode == 0
    assert installed(target) == []
    assert lock.exists()


def test_a_download_failure_is_reported(origin: Origin, target: Path, pull: Pull) -> None:
    result = pull()
    assert result.returncode == 1
    assert "download failed" in result.stderr
    assert "download failed" in state(target, "log")
