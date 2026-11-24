# -*- coding: utf-8 -*-
"""
VIGIL Agent como servico do Windows (pywin32).

  python vigil_service.py --startup auto install   -> registra o servico (inicia com o Windows)
  python vigil_service.py start | stop | remove
  python vigil_service.py --config ... configure|test|collect|run   -> comandos do agente

Tambem e o ponto de entrada do executavel gerado por build_exe.ps1 (VIGIL-Agent.exe).
"""
import os
import sys
import threading

FROZEN = getattr(sys, "frozen", False)
HERE = os.path.dirname(sys.executable if FROZEN else os.path.abspath(__file__))
sys.path.insert(0, HERE)

import servicemanager  # noqa: E402
import win32service  # noqa: E402
import win32serviceutil  # noqa: E402

import vigil_agent  # noqa: E402

AGENT_CMDS = {"configure", "test", "collect", "run"}


class VigilAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "VIGILAgent"
    _svc_display_name_ = "VIGIL Agent"
    _svc_description_ = ("Envia metricas de CPU, memoria, disco, rede e processos ao servidor VIGIL central. "
                         "Somente conexoes de saida (HTTPS); nao permite acesso remoto.")
    # o proprio python.exe (ou o .exe congelado) hospeda o servico -> dispensa pythonservice.exe
    _exe_name_ = sys.executable
    _exe_args_ = "" if FROZEN else '"' + os.path.abspath(__file__) + '"'

    def __init__(self, args):
        super().__init__(args)
        self.stop_evt = threading.Event()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.stop_evt.set()

    def SvcDoRun(self):
        servicemanager.LogInfoMsg("VIGIL Agent iniciado")
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        vigil_agent.run_agent(vigil_agent.default_config_path(), self.stop_evt)
        servicemanager.LogInfoMsg("VIGIL Agent finalizado")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(VigilAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    elif any(a in AGENT_CMDS for a in sys.argv[1:]):
        vigil_agent.main()
    else:
        win32serviceutil.HandleCommandLine(VigilAgentService)
