import os, sys, time
os.environ['AETHER_PLATFORM'] = 'android'
os.environ['AETHER_UI_ENABLED'] = '0'
os.environ['AETHER_WORKER_MODE'] = '1'

def main():
    print('[ANDROID] Starting...')
    try:
        from modules.lan_beacon import start
        start()
        print('[ANDROID] Beacon OK')
    except Exception as e:
        print(f'[ANDROID] Beacon: {e}')
    try:
        from modules.swarm_controller import SwarmController
        SwarmController().enable_swarm()
        print('[ANDROID] Swarm enabled')
    except Exception as e:
        print(f'[ANDROID] Swarm: {e}')
    try:
        from modules.worker_engine import init_worker_engine
        init_worker_engine('android_worker')
        print('[ANDROID] Worker ready')
    except Exception as e:
        print(f'[ANDROID] Worker: {e}')
    print('[ANDROID] Daemon loop running...')
    try:
        while True: time.sleep(10)
    except KeyboardInterrupt:
        print('[ANDROID] Stopped')

if __name__ == '__main__':
    sys.exit(main())
