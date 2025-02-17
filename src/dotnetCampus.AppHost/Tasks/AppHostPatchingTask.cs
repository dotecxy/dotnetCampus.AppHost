﻿using dotnetCampus.AppHosting.Tasks.Models;
using dotnetCampus.EasiPlugins.Tasks.Helpers;

using P = dotnetCampus.AppHosting.Tasks.Models.AppHostPlaceholders;

namespace dotnetCampus.AppHosting.Tasks;

internal class AppHostPatchingTask : CommandLineTask
{
    protected override void RunCore(BuildOptions options)
    {
        Patch(options.AppHostFile.FullName, P.DotNetRoot, options.DotNetRoot, P.DotNetRootName);
        Patch(options.AppHostFile.FullName, P.HostMissingMessage, options.HostMissingMessage, P.HostMissingMessageName);
        Patch(options.AppHostFile.FullName, P.HostMissingUrl, options.HostMissingUrl, P.HostMissingUrlName);
        Patch(options.AppHostFile.FullName, P.NeedPrereqsMessage, options.NeedPrereqsMessage, P.NeedPrereqsMessageName);
        Patch(options.AppHostFile.FullName, P.NeedPrereqsUrl, options.NeedPrereqsMessage, P.NeedPrereqsUrlName);
    }

    private static void Patch(string appHostExeFilePath, string placeholder, string? value, string placeholderName)
    {
        var patcher = new AppHostPatcher(appHostExeFilePath, placeholder, placeholderName);
        if (!string.IsNullOrWhiteSpace(value))
        {
            patcher.Patch(value);
        }
    }
}
