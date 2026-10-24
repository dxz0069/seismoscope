import os


def build_prompt(base_prompt, external_content):
    prompt = base_prompt + external_content
    return prompt


def deployment_tool(command):
    return os.system(command)
