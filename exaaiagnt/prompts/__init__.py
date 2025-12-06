from pathlib import Path

from jinja2 import Environment


def get_available_prompt_modules() -> dict[str, list[str]]:
    modules_dir = Path(__file__).parent
    available_modules = {}

    for category_dir in modules_dir.iterdir():
        if category_dir.is_dir() and not category_dir.name.startswith("__"):
            category_name = category_dir.name
            modules = []

            for file_path in category_dir.glob("*.jinja"):
                module_name = file_path.stem
                modules.append(module_name)

            if modules:
                available_modules[category_name] = sorted(modules)

    return available_modules


def get_all_module_names() -> set[str]:
    all_modules = set()
    for category_modules in get_available_prompt_modules().values():
        all_modules.update(category_modules)
    return all_modules


def auto_detect_modules(target: str, instruction: str = "") -> list[str]:
    """
    Automatically detect and return relevant prompt modules based on target and instruction.
    
    Args:
        target: The target URL or domain
        instruction: The user's instruction
        
    Returns:
        List of auto-detected module names
    """
    try:
        from exaaiagnt.prompts.auto_loader import detect_modules_from_target
        return detect_modules_from_target(target, instruction)
    except ImportError:
        return []


def get_smart_modules(target: str, instruction: str = "", user_modules: list[str] | None = None) -> list[str]:
    """
    Get final list of modules combining user-specified and auto-detected modules.
    
    Args:
        target: The target URL or domain
        instruction: The user's instruction
        user_modules: Modules explicitly specified by user
        
    Returns:
        Combined list of modules (user + auto-detected, max 5)
    """
    final_modules = set(user_modules or [])
    
    # Auto-detect if user didn't specify modules
    if not user_modules:
        auto_modules = auto_detect_modules(target, instruction)
        final_modules.update(auto_modules)
    
    # Validate and limit to 5
    available = get_all_module_names()
    valid_modules = [m for m in final_modules if m in available]
    
    return valid_modules[:5]


def validate_module_names(module_names: list[str]) -> dict[str, list[str]]:
    available_modules = get_all_module_names()
    valid_modules = []
    invalid_modules = []

    for module_name in module_names:
        if module_name in available_modules:
            valid_modules.append(module_name)
        else:
            invalid_modules.append(module_name)

    return {"valid": valid_modules, "invalid": invalid_modules}


def generate_modules_description() -> str:
    available_modules = get_available_prompt_modules()

    if not available_modules:
        return "No prompt modules available"

    all_module_names = get_all_module_names()

    if not all_module_names:
        return "No prompt modules available"

    sorted_modules = sorted(all_module_names)
    modules_str = ", ".join(sorted_modules)

    description = (
        f"List of prompt modules to load for this agent (max 5). Available modules: {modules_str}. "
    )

    example_modules = sorted_modules[:2]
    if example_modules:
        example = f"Example: {', '.join(example_modules)} for specialized agent"
        description += example

    return description


def load_prompt_modules(module_names: list[str], jinja_env: Environment) -> dict[str, str]:
    import logging

    logger = logging.getLogger(__name__)
    module_content = {}
    prompts_dir = Path(__file__).parent

    available_modules = get_available_prompt_modules()

    for module_name in module_names:
        try:
            module_path = None

            if "/" in module_name:
                module_path = f"{module_name}.jinja"
            else:
                for category, modules in available_modules.items():
                    if module_name in modules:
                        module_path = f"{category}/{module_name}.jinja"
                        break

                if not module_path:
                    root_candidate = f"{module_name}.jinja"
                    if (prompts_dir / root_candidate).exists():
                        module_path = root_candidate

            if module_path and (prompts_dir / module_path).exists():
                template = jinja_env.get_template(module_path)
                var_name = module_name.split("/")[-1]
                module_content[var_name] = template.render()
                logger.info(f"Loaded prompt module: {module_name} -> {var_name}")
            else:
                logger.warning(f"Prompt module not found: {module_name}")

        except (FileNotFoundError, OSError, ValueError) as e:
            logger.warning(f"Failed to load prompt module {module_name}: {e}")

    return module_content
