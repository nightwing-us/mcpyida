# Standard Libraries
import os
from pathlib import Path


res_path = Path(__file__).parent.resolve() / 'ida_plugin'
plugin_file = res_path / 'mcpyida_proxy.py'


def install() -> None:
    idausr_var = os.getenv('IDAUSR', '')
    if not idausr_var:
        if os.name == 'nt':
            appdata = Path(str(os.getenv('APPDATA')))
            idausr = appdata / 'Hex-Rays' / 'IDA Pro'
        else:
            idausr = Path.home() / '.idapro'
    else:
        idausr = Path(idausr_var)

    if not idausr.exists():
        print('Could not find IDAUSR path')

    plugins_dir = idausr / 'plugins'
    plugins_dir.mkdir(parents=True, exist_ok=True)

    print(f'Found IDA Plugins Directory: {plugins_dir}')
    print('Installing plugin...')
    plugin_contents = plugin_file.read_text()
    with open(plugins_dir / 'mcpyida_proxy.py', 'w') as f:
        f.write(plugin_contents)
    print('Done')
