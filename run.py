import subprocess
import argparse

RT = 30
BS = 64

def run(threads, args):

    threads = '0' if threads == 1 else f'0-{threads - 1}'
    cmd = './build/dpdk-ping -l {} -a {},llq_policy={} -- --sip {} --dip {} --dmac {} --flows {} --bs {} --mode FORWARD --rt {} --ntx {}'.format(threads, *args)
    output = subprocess.run(cmd.split(' '), capture_output=True, text=True)
    print(output)
    if output is None:
        raise RuntimeError
    else:
        output = list(filter(lambda l : l.startswith('Submitted PPS:'), output.stdout.split('\n')))
    if not output:
        raise RuntimeError
    pps = output[0].split(' ')[-1]
    return pps

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--sip', help='Source IP', dest='sip', nargs='?',
                        required=True, type=str)
    parser.add_argument('--dip',  help='Dest IP', dest='dip', nargs='?',
                        required=True, type=str)
    parser.add_argument('--dmac',  help='Dest Mac',
                        dest='dmac', nargs='?', required=True, type=str)

    args = parser.parse_args()
    sip = args.sip
    dip = args.dip
    dmac = args.dmac

    threads = [1, 2, 4, 8, 16]
    ntx = [1, 2, 4, 8, 16]
    pci = '00:06.0'
    llq_policy = 2
    res = {}

    for tx in ntx:
        pps = run(threads = 1, args = [pci, llq_policy, sip, dip, dmac, tx, BS, RT, tx])
        res[(1, tx)] = pps

    for t in threads:
        pps = run(threads = t, args = [pci, llq_policy, sip, dip, dmac, 1, BS, RT, 1])
        res[(t, 1)] = pps

    result = []
    print('Threads  TX  llq_policy  pps')
    for (thrds, tx), pps in res.items():
        result.append((thrds, tx, llq_policy, pps))
    print(result)

if __name__ == '__main__':
    main()

