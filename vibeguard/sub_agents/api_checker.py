"""APIChecker sub-agent for VibeGuard.

Detects *hallucinated* API calls — function or method invocations on
imported packages that do not actually exist in those packages.  AI code
generators sometimes invent plausible-sounding but non-existent functions;
this agent catches them via AST analysis cross-referenced against a curated
database of known public APIs.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Any

from google.adk.agents import Agent

# ---------------------------------------------------------------------------
# Known API surface per popular package
# ---------------------------------------------------------------------------
# Each key maps to a *set* of top-level public names (functions, classes,
# constants) that legitimately exist in that package's public interface.
# This is intentionally conservative — we only flag calls we are *sure*
# should not exist.
# ---------------------------------------------------------------------------

KNOWN_APIS: dict[str, set[str]] = {
    # --- HTTP / Networking ---
    "requests": {
        "get", "post", "put", "delete", "patch", "head", "options",
        "request", "Session", "Response", "PreparedRequest",
        "Request", "HTTPError", "ConnectionError", "Timeout",
        "URLRequired", "TooManyRedirects", "RequestException",
        "codes", "auth", "cookies", "exceptions", "hooks",
        "models", "sessions", "structures", "utils", "adapters",
        "packages", "compat", "api",
    },
    "httpx": {
        "get", "post", "put", "delete", "patch", "head", "options",
        "request", "stream", "Client", "AsyncClient", "Response",
        "Request", "URL", "Headers", "QueryParams", "Cookies",
        "Timeout", "Limits", "HTTPError", "RequestError",
        "HTTPStatusError", "TimeoutException", "ConnectError",
        "BasicAuth", "DigestAuth", "codes",
    },
    # --- Web Frameworks ---
    "flask": {
        "Flask", "render_template", "render_template_string",
        "redirect", "url_for", "request", "jsonify", "Blueprint",
        "make_response", "abort", "flash", "get_flashed_messages",
        "session", "g", "current_app", "send_file",
        "send_from_directory", "Response", "Request",
        "after_this_request", "has_request_context",
        "has_app_context", "cli", "Config", "testing",
        "templating", "signals", "json", "wrappers",
    },
    "fastapi": {
        "FastAPI", "APIRouter", "Depends", "Query", "Path", "Body",
        "Header", "Cookie", "Form", "File", "UploadFile",
        "HTTPException", "Request", "Response", "WebSocket",
        "BackgroundTasks", "Security", "status",
        "encoders", "middleware", "params", "routing",
        "staticfiles", "templating", "testclient",
        "responses", "security",
    },
    "django": {
        "setup", "conf", "urls", "views", "http", "db", "forms",
        "template", "test", "utils", "core", "contrib",
        "middleware", "dispatch", "shortcuts",
    },
    # --- AI / ML ---
    "openai": {
        "OpenAI", "AsyncOpenAI", "AzureOpenAI", "AsyncAzureOpenAI",
        "ChatCompletion", "Completion", "Client",
        "api_key", "api_base", "api_type", "api_version",
        "Embedding", "Image", "Audio", "Moderation", "Model",
        "File", "FineTune", "FineTuning", "error", "resources",
        "types", "BadRequestError", "AuthenticationError",
        "PermissionDeniedError", "NotFoundError",
        "APIConnectionError", "RateLimitError", "APIStatusError",
    },
    "langchain": {
        "LLMChain", "ConversationChain", "SequentialChain",
        "SimpleSequentialChain", "TransformChain",
        "RetrievalQA", "VectorDBQA",
        "PromptTemplate", "ChatPromptTemplate",
        "FewShotPromptTemplate",
        "LLM", "ChatOpenAI", "OpenAI",
        "agents", "callbacks", "chains", "chat_models",
        "document_loaders", "embeddings", "llms", "memory",
        "output_parsers", "prompts", "retrievers", "schema",
        "text_splitter", "tools", "utilities", "vectorstores",
    },
    "transformers": {
        "AutoModel", "AutoModelForCausalLM",
        "AutoModelForSequenceClassification",
        "AutoModelForTokenClassification",
        "AutoModelForQuestionAnswering",
        "AutoModelForSeq2SeqLM",
        "AutoModelForMaskedLM",
        "AutoTokenizer", "AutoConfig", "AutoFeatureExtractor",
        "AutoProcessor", "AutoImageProcessor",
        "pipeline", "Pipeline",
        "Trainer", "TrainingArguments",
        "BertModel", "BertTokenizer", "BertConfig",
        "GPT2Model", "GPT2Tokenizer", "GPT2Config",
        "T5Model", "T5Tokenizer", "T5Config",
        "RobertaModel", "RobertaTokenizer",
        "set_seed", "logging",
        "PreTrainedModel", "PreTrainedTokenizer",
        "PretrainedConfig", "BatchEncoding",
        "DataCollatorWithPadding",
        "DataCollatorForLanguageModeling",
        "GenerationConfig", "StoppingCriteria",
    },
    # --- Deep Learning ---
    "torch": {
        "tensor", "Tensor", "zeros", "ones", "rand", "randn",
        "randint", "arange", "linspace", "logspace",
        "eye", "empty", "full", "cat", "stack", "split",
        "chunk", "squeeze", "unsqueeze", "reshape", "flatten",
        "transpose", "permute", "contiguous", "clone", "detach",
        "no_grad", "enable_grad", "set_grad_enabled",
        "save", "load", "manual_seed",
        "nn", "optim", "utils", "cuda", "backends",
        "autograd", "jit", "onnx", "distributed",
        "functional", "hub", "amp",
        "float16", "float32", "float64", "int8", "int16",
        "int32", "int64", "bool", "complex64", "complex128",
        "device", "dtype", "is_tensor",
        "sigmoid", "relu", "softmax", "tanh",
        "matmul", "mm", "bmm", "dot", "einsum",
        "sum", "mean", "max", "min", "abs", "sqrt", "exp", "log",
        "clamp", "clip", "where", "topk", "sort", "argmax",
        "argmin", "pow", "norm",
    },
    "tensorflow": {
        "constant", "Variable", "function", "GradientTape",
        "Module", "keras", "data", "distribute",
        "saved_model", "lite", "summary",
        "math", "linalg", "signal", "image", "io", "strings",
        "debugging", "config", "nest", "ragged",
        "zeros", "ones", "fill", "eye", "range",
        "cast", "reshape", "transpose", "expand_dims",
        "squeeze", "concat", "stack", "split", "tile", "gather",
        "reduce_sum", "reduce_mean", "reduce_max", "reduce_min",
        "matmul", "tensordot",
        "float16", "float32", "float64", "int32", "int64",
        "bool", "string",
        "TensorSpec", "RaggedTensor", "SparseTensor",
        "nn", "train", "estimator", "feature_column",
    },
    # --- Data Science ---
    "numpy": {
        "array", "ndarray", "zeros", "ones", "empty", "full",
        "arange", "linspace", "logspace", "eye", "identity",
        "meshgrid", "mgrid", "ogrid",
        "concatenate", "stack", "vstack", "hstack", "dstack",
        "split", "hsplit", "vsplit",
        "reshape", "ravel", "flatten", "transpose", "swapaxes",
        "expand_dims", "squeeze",
        "sum", "mean", "std", "var", "min", "max",
        "argmin", "argmax", "cumsum", "cumprod",
        "dot", "matmul", "inner", "outer", "cross", "einsum",
        "linalg", "random", "fft",
        "sin", "cos", "tan", "exp", "log", "log2", "log10",
        "sqrt", "abs", "sign", "ceil", "floor", "round",
        "clip", "where", "select", "sort", "argsort",
        "unique", "searchsorted",
        "save", "load", "savez", "loadtxt", "savetxt", "genfromtxt",
        "float16", "float32", "float64", "int8", "int16",
        "int32", "int64", "bool_", "complex64", "complex128",
        "inf", "nan", "pi", "e", "newaxis",
        "dtype", "isnan", "isinf", "isfinite",
        "allclose", "array_equal", "testing",
    },
    "pandas": {
        "DataFrame", "Series", "Index", "MultiIndex",
        "Categorical", "CategoricalIndex",
        "DatetimeIndex", "TimedeltaIndex", "PeriodIndex",
        "Timestamp", "Timedelta", "Period",
        "read_csv", "read_excel", "read_json", "read_sql",
        "read_parquet", "read_feather", "read_hdf",
        "read_pickle", "read_html", "read_clipboard",
        "read_table", "read_fwf", "read_gbq",
        "concat", "merge", "melt", "pivot", "pivot_table",
        "crosstab", "cut", "qcut", "get_dummies",
        "to_datetime", "to_timedelta", "to_numeric",
        "date_range", "period_range", "timedelta_range",
        "isna", "isnull", "notna", "notnull",
        "set_option", "get_option", "reset_option",
        "option_context", "options", "testing",
        "NA", "NaT", "api", "io", "errors",
        "Grouper", "NamedAgg",
    },
    # --- ORM / DB ---
    "sqlalchemy": {
        "create_engine", "engine", "text", "select", "insert",
        "update", "delete", "and_", "or_", "not_", "func",
        "Column", "Integer", "String", "Float", "Boolean",
        "DateTime", "Date", "Text", "ForeignKey", "Table",
        "MetaData", "inspect", "event",
        "Session", "sessionmaker", "scoped_session",
        "declarative_base", "relationship", "backref",
        "orm", "exc", "pool", "types", "schema",
    },
    # --- AWS ---
    "boto3": {
        "client", "resource", "Session",
        "set_stream_logger", "setup_default_session",
        "NullHandler", "utils", "exceptions",
        "docs", "resources", "session",
    },
    # --- ML (sklearn) ---
    "sklearn": {
        "base", "calibration", "cluster", "compose",
        "covariance", "cross_decomposition",
        "datasets", "decomposition", "discriminant_analysis",
        "dummy", "ensemble", "exceptions", "experimental",
        "externals", "feature_extraction", "feature_selection",
        "gaussian_process", "impute", "inspection",
        "isotonic", "kernel_approximation", "kernel_ridge",
        "linear_model", "manifold", "metrics", "mixture",
        "model_selection", "multiclass", "multioutput",
        "naive_bayes", "neighbors", "neural_network",
        "pipeline", "preprocessing", "random_projection",
        "semi_supervised", "svm", "tree", "utils",
        "config_context", "get_config", "set_config",
        "show_versions",
    },
    # --- Validation ---
    "pydantic": {
        "BaseModel", "Field", "validator", "root_validator",
        "BaseSettings", "ValidationError", "AnyUrl", "EmailStr",
        "HttpUrl", "SecretStr", "conint", "confloat", "constr",
        "conlist", "conset",
        "model_validator", "field_validator", "ConfigDict",
        "computed_field", "TypeAdapter",
        "PrivateAttr", "create_model",
    },
    # --- Task Queues ---
    "celery": {
        "Celery", "Task", "chain", "group", "chord", "shared_task",
        "current_app", "current_task",
        "app", "beat", "bin", "canvas", "concurrency",
        "exceptions", "loaders", "platforms", "result",
        "schedules", "signals", "states", "utils", "worker",
    },
    # --- Redis ---
    "redis": {
        "Redis", "StrictRedis", "ConnectionPool",
        "Sentinel", "SentinelConnectionPool",
        "RedisCluster", "ClusterConnectionPool",
        "from_url", "BlockingConnectionPool",
        "Connection", "SSLConnection",
        "ConnectionError", "TimeoutError", "RedisError",
        "AuthenticationError", "BusyLoadingError",
        "ResponseError", "DataError", "PubSubError",
        "client", "cluster", "commands", "exceptions",
        "sentinel", "utils",
    },
    # --- Testing ---
    "pytest": {
        "fixture", "mark", "param", "raises", "warns",
        "skip", "xfail", "fail", "exit",
        "importorskip", "approx", "deprecated_call",
        "MonkeyPatch", "TempdirFactory", "TempPathFactory",
        "LogCaptureFixture", "CaptureFixture",
        "main", "register_assert_rewrite",
        "freeze_includes", "Item", "Collector",
        "Session", "Module", "Class", "Function",
    },
    # --- Image Processing ---
    "PIL": {
        "Image", "ImageDraw", "ImageFont", "ImageFilter",
        "ImageEnhance", "ImageOps", "ImageColor",
        "ImageChops", "ImageStat", "ImageFile",
        "ImageSequence", "ImagePalette", "ImagePath",
        "ImageTransform", "ImageMath", "ImageGrab",
        "ExifTags", "TiffTags", "TiffImagePlugin",
        "PngImagePlugin", "JpegImagePlugin",
        "GifImagePlugin", "BmpImagePlugin",
        "UnidentifiedImageError",
    },
    "pillow": {  # alias
        "Image", "ImageDraw", "ImageFont", "ImageFilter",
        "ImageEnhance", "ImageOps",
    },
}


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _extract_imports(tree: ast.AST) -> dict[str, str]:
    """Return a mapping of *local alias → module name* for ``import X`` stmts.

    Only plain module imports (``import X`` / ``import X as Y``) are mapped,
    because a call like ``Y.foo()`` is genuinely ``X.foo()`` and can be
    validated against the module's public API.

    ``from X import Y`` is deliberately **excluded**: there ``Y`` is a *member*
    of the module (an object, class, or function), not the module itself, so
    ``Y.foo()`` is an attribute access on that member — not ``X.foo()``.
    Mapping it would produce false positives (e.g. ``from flask import request``
    followed by the perfectly valid ``request.args.get(...)`` being flagged as
    a non-existent ``flask.args`` call).
    """
    alias_map: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name
                # Map to the top-level package name
                top_level = alias.name.split(".")[0]
                alias_map[local] = top_level

    return alias_map


def _extract_attribute_calls(
    tree: ast.AST,
    alias_map: dict[str, str],
) -> list[dict[str, Any]]:
    """Find ``alias.func()`` calls where *alias* is an imported module."""
    calls: list[dict[str, Any]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func

        # Pattern: module.function(...)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            obj_name = func.value.id
            if obj_name in alias_map:
                calls.append(
                    {
                        "line_number": getattr(node, "lineno", 0),
                        "alias": obj_name,
                        "module": alias_map[obj_name],
                        "called_function": func.attr,
                    }
                )

        # Pattern: module.sub.function(...)  (two-level attribute)
        elif (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Attribute)
            and isinstance(func.value.value, ast.Name)
        ):
            obj_name = func.value.value.id
            if obj_name in alias_map:
                calls.append(
                    {
                        "line_number": getattr(node, "lineno", 0),
                        "alias": obj_name,
                        "module": alias_map[obj_name],
                        "called_function": f"{func.value.attr}.{func.attr}",
                    }
                )

    return calls


# ---------------------------------------------------------------------------
# Tool function
# ---------------------------------------------------------------------------


def check_api_calls(repo_path: str) -> dict[str, Any]:
    """Detect hallucinated API calls in Python files under *repo_path*.

    Parses each ``.py`` file with the ``ast`` module, extracts import
    statements and attribute-style calls on imported modules, then
    cross-references against :data:`KNOWN_APIS`.

    Args:
        repo_path: Absolute path to the repository root.

    Returns:
        A dict with ``findings`` (list of per-call results),
        ``total_hallucinated_calls``, and ``total_files_scanned``.
    """
    repo = Path(repo_path)
    if not repo.is_dir():
        return {
            "findings": [],
            "total_hallucinated_calls": 0,
            "total_files_scanned": 0,
            "error": f"Repository path does not exist or is not a directory: {repo_path}",
        }

    findings: list[dict[str, Any]] = []
    files_scanned = 0

    skip_dirs = {
        "node_modules", ".git", "__pycache__", ".venv", "venv",
        "env", ".tox", ".mypy_cache", "dist", "build",
    }

    for dirpath, _dirnames, filenames in os.walk(repo):
        rel = os.path.relpath(dirpath, repo)
        if any(part in skip_dirs for part in Path(rel).parts):
            continue

        for filename in filenames:
            if not filename.endswith(".py"):
                continue

            filepath = os.path.join(dirpath, filename)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
                    source = fh.read()
            except (OSError, IOError):
                continue

            try:
                tree = ast.parse(source, filename=filepath)
            except SyntaxError:
                continue

            files_scanned += 1

            alias_map = _extract_imports(tree)
            calls = _extract_attribute_calls(tree, alias_map)

            rel_filepath = os.path.relpath(filepath, repo)

            for call_info in calls:
                module = call_info["module"]
                func_name = call_info["called_function"]

                # Only check modules we have in our database
                if module not in KNOWN_APIS:
                    continue

                known = KNOWN_APIS[module]
                # For nested calls like ``np.random.seed``, check the
                # first component (``random``) which is a sub-module.
                top_attr = func_name.split(".")[0]
                exists = top_attr in known

                if not exists:
                    # Build a helpful suggestion
                    suggestion = _suggest_alternative(module, func_name, known)

                    findings.append(
                        {
                            "file": rel_filepath,
                            "line_number": call_info["line_number"],
                            "module": module,
                            "called_function": func_name,
                            "exists_in_api": False,
                            "suggestion": suggestion,
                        }
                    )

    findings.sort(key=lambda f: (f["file"], f["line_number"]))

    return {
        "findings": findings,
        "total_hallucinated_calls": len(findings),
        "total_files_scanned": files_scanned,
    }


def _suggest_alternative(
    module: str, called: str, known: set[str]
) -> str:
    """Return a human-readable suggestion for a non-existent API call.

    Uses simple Levenshtein-style heuristic (common-prefix length) to
    find the closest match in *known*.
    """
    top_attr = called.split(".")[0]

    # Quick "did you mean?" via longest common prefix
    best_match = ""
    best_score = 0
    for candidate in known:
        # Simple similarity: count matching leading characters
        score = sum(
            1 for a, b in zip(top_attr.lower(), candidate.lower()) if a == b
        )
        if score > best_score:
            best_score = score
            best_match = candidate

    if best_match and best_score >= 2:
        return (
            f"'{module}.{called}' does not exist. "
            f"Did you mean '{module}.{best_match}'?"
        )
    return (
        f"'{module}.{called}' does not exist in the '{module}' package. "
        f"Verify the correct function name in the official documentation."
    )


# ---------------------------------------------------------------------------
# Agent definition
# ---------------------------------------------------------------------------

api_checker_agent = Agent(
    name="APIChecker",
    model=os.getenv("VIBEGUARD_MODEL", "gemini-2.5-flash-lite"),
    description=(
        "Detects hallucinated API calls — function or method invocations on "
        "imported packages that do not actually exist in those packages. "
        "AI code generators sometimes invent plausible-sounding but "
        "non-existent functions."
    ),
    instruction=(
        "You are the APIChecker agent. Your job is to detect hallucinated "
        "API calls — function or method calls on imported packages that "
        "don't actually exist in those packages. AI code generators "
        "sometimes invent plausible-sounding but non-existent functions.\n\n"
        "Use the check_api_calls tool on the repo path. Summarize which "
        "calls appear hallucinated, which module they belong to, and what "
        "the correct API might be. Store findings in session state under "
        "'api_findings'."
    ),
    tools=[check_api_calls],
)
