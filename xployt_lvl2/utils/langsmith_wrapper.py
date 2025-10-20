"""LangSmith wrapper for OpenAI API calls to enable tracing and monitoring."""
import os
from typing import Any, Optional, Callable
from openai import OpenAI
from xployt_lvl2.config.settings import settings

# Initialize LangSmith environment - REQUIRED
if not settings.langsmith_api_key:
    raise RuntimeError(
        "LangSmith API key not configured. Set LANGSMITH_API_KEY in .env file. "
        "Get your API key from https://smith.langchain.com/"
    )

if not settings.langsmith_tracing:
    raise RuntimeError(
        "LangSmith tracing is disabled. Set LANGSMITH_TRACING=true in .env file."
    )

os.environ["LANGSMITH_API_KEY"] = settings.langsmith_api_key
os.environ["LANGSMITH_PROJECT"] = settings.langsmith_project
os.environ["LANGSMITH_TRACING"] = "true"

# Verify langsmith package is installed
try:
    from langsmith import traceable
except ImportError:
    raise RuntimeError(
        "LangSmith package not installed. Run: poetry install"
    )


def get_traced_openai_client(run_name: Optional[str] = None) -> OpenAI:
    """
    Get an OpenAI client. LangSmith tracing is always enabled.
    
    Args:
        run_name: Optional name for context (not used with @traceable pattern)
        
    Returns:
        OpenAI client instance
    """
    print(f"✓ LangSmith tracing enabled for project: {settings.langsmith_project}")
    if run_name:
        print(f"  Context: {run_name}")
    
    return OpenAI(api_key=settings.openai_api_key)


def trace_llm_call(func: Callable = None, *, run_type: str = "llm", name: Optional[str] = None):
    """
    Decorator to trace LLM function calls with LangSmith using @traceable.
    LangSmith tracing is always enabled - will raise error if not configured.
    
    Usage:
        @trace_llm_call
        def my_llm_function():
            client = get_traced_openai_client()
            response = client.chat.completions.create(...)
            return response
        
        # Or with custom name:
        @trace_llm_call(name="custom-operation", run_type="chain")
        def my_pipeline():
            ...
    """
    from langsmith import traceable
    
    def decorator(f):
        return traceable(name=name or f.__name__, run_type=run_type)(f)
    
    # Support both @trace_llm_call and @trace_llm_call()
    if func is not None:
        return decorator(func)
    return decorator


def traced_chat_completion(
    messages: list[dict],
    model: str = None,
    temperature: float = None,
    max_tokens: int = None,
    operation_name: str = "llm-call",
    **kwargs
) -> str:
    """
    Make a traced OpenAI chat completion call.
    
    This is a drop-in replacement for client.chat.completions.create() that automatically
    traces the call in LangSmith.
    
    Args:
        messages: List of message dicts with 'role' and 'content'
        model: Model to use (defaults to settings.llm_model)
        temperature: Temperature setting (defaults to settings.temperature)
        max_tokens: Max tokens to generate
        operation_name: Name for this operation in LangSmith traces
        **kwargs: Additional arguments to pass to OpenAI API
        
    Returns:
        The content of the first choice from the response
        
    Example:
        response = traced_chat_completion(
            messages=[{"role": "user", "content": "Hello"}],
            operation_name="greet-user"
        )
    """
    from langsmith import traceable, wrappers
    
    @traceable(name=operation_name, run_type="llm")
    def _call():
        # Create and wrap the OpenAI client for automatic tracing
        client = OpenAI(api_key=settings.openai_api_key)
        wrapped_client = wrappers.wrap_openai(client)
        
        # Build API call parameters - only required params
        api_params = {
            "model": model or settings.llm_model,
            "messages": messages,
        }
        
        # Only include optional parameters if explicitly provided
        if temperature is not None:
            api_params["temperature"] = temperature
            
        if max_tokens is not None:
            api_params["max_tokens"] = max_tokens
        
        # Add any additional kwargs, filtering out None values
        for key, value in kwargs.items():
            if value is not None:
                api_params[key] = value
        
        response = wrapped_client.chat.completions.create(**api_params)
        return response.choices[0].message.content
    
    return _call()


def traced_chat_completion_raw(
    messages: list[dict],
    model: str = None,
    temperature: float = None,
    max_tokens: int = None,
    operation_name: str = "llm-call",
    **kwargs
):
    """
    Make a traced OpenAI chat completion call and return the full response object.
    
    Same as traced_chat_completion but returns the complete response object instead
    of just the message content.
    
    Args:
        messages: List of message dicts with 'role' and 'content'
        model: Model to use (defaults to settings.llm_model)
        temperature: Temperature setting
        max_tokens: Max tokens to generate
        operation_name: Name for this operation in LangSmith traces
        **kwargs: Additional arguments to pass to OpenAI API
        
    Returns:
        The full ChatCompletion response object
        
    Example:
        response = traced_chat_completion_raw(
            messages=[{"role": "user", "content": "Hello"}],
            operation_name="greet-user"
        )
        content = response.choices[0].message.content
        tokens = response.usage.total_tokens
    """
    from langsmith import traceable, wrappers
    
    @traceable(name=operation_name, run_type="llm")
    def _call():
        # Create and wrap the OpenAI client for automatic tracing
        client = OpenAI(api_key=settings.openai_api_key)
        wrapped_client = wrappers.wrap_openai(client)
        
        # Build API call parameters - only required params
        api_params = {
            "model": model or settings.llm_model,
            "messages": messages,
        }
        
        # Only include optional parameters if explicitly provided
        if temperature is not None:
            api_params["temperature"] = temperature
            
        if max_tokens is not None:
            api_params["max_tokens"] = max_tokens
        
        # Add any additional kwargs, filtering out None values
        for key, value in kwargs.items():
            if value is not None:
                api_params[key] = value
        
        return wrapped_client.chat.completions.create(**api_params)
    
    return _call()


def traced_gpt5_completion(
    messages: list[dict],
    model: str = "gpt-5",
    max_completion_tokens: int = None,
    reasoning_effort: str = None,
    operation_name: str = "gpt5-call",
    stream: bool = False,
    **kwargs
) -> str:
    """
    Make a traced GPT-5 or GPT-5-mini chat completion call.
    
    GPT-5 models have different parameters than GPT-4:
    - Use max_completion_tokens instead of max_tokens
    - Support reasoning_effort parameter
    - Don't support temperature parameter
    
    Args:
        messages: List of message dicts with 'role' and 'content'
        model: Model to use ("gpt-5" or "gpt-5-mini", defaults to "gpt-5")
        max_completion_tokens: Maximum tokens to generate in completion
        reasoning_effort: Reasoning effort level (e.g., "minimal", "low", "medium", "high")
        operation_name: Name for this operation in LangSmith traces
        stream: Whether to stream the response
        **kwargs: Additional arguments to pass to OpenAI API
        
    Returns:
        The content of the first choice from the response
        
    Example:
        response = traced_gpt5_completion(
            messages=[{"role": "user", "content": "Hello"}],
            model="gpt-5-mini",
            max_completion_tokens=256,
            reasoning_effort="minimal",
            operation_name="fast-gpt5-call"
        )
    """
    from langsmith import traceable, wrappers
    
    @traceable(name=operation_name, run_type="llm")
    def _call():
        # Create and wrap the OpenAI client for automatic tracing
        client = OpenAI(api_key=settings.openai_api_key)
        wrapped_client = wrappers.wrap_openai(client)
        
        # Build API call parameters - only required params
        api_params = {
            "model": model,
            "messages": messages,
            "stream": stream,
        }
        
        # Only include optional parameters if explicitly provided
        if max_completion_tokens is not None:
            api_params["max_completion_tokens"] = max_completion_tokens
            
        if reasoning_effort is not None:
            api_params["reasoning_effort"] = reasoning_effort
        
        # Add any additional kwargs, filtering out None values
        for key, value in kwargs.items():
            if value is not None:
                api_params[key] = value
        
        response = wrapped_client.chat.completions.create(**api_params)
        return response.choices[0].message.content
    
    return _call()


def traced_gpt5_completion_raw(
    messages: list[dict],
    model: str = "gpt-5",
    max_completion_tokens: int = None,
    reasoning_effort: str = None,
    operation_name: str = "gpt5-call",
    stream: bool = False,
    **kwargs
):
    """
    Make a traced GPT-5 or GPT-5-mini chat completion call and return the full response object.
    
    Same as traced_gpt5_completion but returns the complete response object instead
    of just the message content.
    
    Args:
        messages: List of message dicts with 'role' and 'content'
        model: Model to use ("gpt-5" or "gpt-5-mini", defaults to "gpt-5")
        max_completion_tokens: Maximum tokens to generate in completion
        reasoning_effort: Reasoning effort level (e.g., "minimal", "low", "medium", "high")
        operation_name: Name for this operation in LangSmith traces
        stream: Whether to stream the response
        **kwargs: Additional arguments to pass to OpenAI API
        
    Returns:
        The full ChatCompletion response object
        
    Example:
        response = traced_gpt5_completion_raw(
            messages=[{"role": "user", "content": "Hello"}],
            model="gpt-5-mini",
            max_completion_tokens=256,
            reasoning_effort="minimal"
        )
        content = response.choices[0].message.content
        tokens = response.usage.total_tokens
    """
    from langsmith import traceable, wrappers
    
    @traceable(name=operation_name, run_type="llm")
    def _call():
        # Create and wrap the OpenAI client for automatic tracing
        client = OpenAI(api_key=settings.openai_api_key)
        wrapped_client = wrappers.wrap_openai(client)
        
        # Build API call parameters - only required params
        api_params = {
            "model": model,
            "messages": messages,
            "stream": stream,
        }
        
        # Only include optional parameters if explicitly provided
        if max_completion_tokens is not None:
            api_params["max_completion_tokens"] = max_completion_tokens
            
        if reasoning_effort is not None:
            api_params["reasoning_effort"] = reasoning_effort
        
        # Add any additional kwargs, filtering out None values
        for key, value in kwargs.items():
            if value is not None:
                api_params[key] = value
        
        return wrapped_client.chat.completions.create(**api_params)
    
    return _call()


__all__ = [
    "get_traced_openai_client",
    "trace_llm_call",
    "traced_chat_completion",
    "traced_chat_completion_raw",
    "traced_gpt5_completion",
    "traced_gpt5_completion_raw"
]