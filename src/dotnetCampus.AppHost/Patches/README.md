# .NET Runtime �ֿⲹ��˵��

## AppHost.exe ���뷽��

### Ӧ�ô��벹��

1. ��¡ dotnet/runtime �ֿ�
2. �л����ļ�������Ӧ�� Tag�������л��� v6.0.1 �� Tag��
3. �� dotnet/runtime ����·���£�ʹ������Ӧ�� git �����ļ�
    * `git am <patch_file>`

### �޸������ɴ��벹��

1. �޸Ĳ��ύ���루����ϲ��ύ�����ٲ����������Ա�˲ֿ���� Patches �ļ��и��׶���
2. ʹ������������ļ�
    * `git format-patch <tag>`��������ᴴ����ǰ��֧��ָ�� Tag ֮�������ύ�Ĳ�����

### ���� AppHost

1. ʹ����Щ����������ͬ�汾�� AppHost����ȫ������ʱ��Լ 15 ���ӣ���ǰ 2 ���ӾͿ��Եõ� AppHost ����������ļ���
    * x64: `.\build.cmd -a x64 -c Release`
    * x86: `.\build.cmd -a x86 -c Release`
2. ȥ��Щ·���ҵ� AppHost ����ļ�
    * x64: `.\artifacts\bin\win-x64.Release\corehost`
    * x86: `.\artifacts\bin\win-x86.Release\corehost`
3. ���ҵ�������ļ�����������Ŀ�� Assets\template ��Ӧ�Ŀ���ļ�����
