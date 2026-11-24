export const zh = {
  attachmentCollector: {
    confirm: '是否要递归收集以下文件夹中所有笔记的附件？\n{{folders}}\n此操作无法撤销。',
    progressBar: {
      message: '正在收集附件 {{iterationString}} - \'{{noteFilePath}}\'。',
      title: '正在收集附件...'
    }
  },
  buttons: {
    copy: '复制',
    move: '移动',
    previewAttachmentFile: '预览附件文件',
    skip: '跳过'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: '附件 {{attachment}} 被多个笔记引用。',
    heading: '正在收集被多个笔记使用的附件',
    noPriorityWinnerReason: {
      EmptyList: '未移动，因为 {{settingName}} 设置为空，没有依据判断这些笔记中哪一个拥有它。',
      NoMatch: '未移动，因为这些笔记均不匹配 {{settingName}} 设置中的任何条目。',
      Tie: '未移动，因为这些笔记中有多个与 {{settingName}} 设置匹配程度相同，无法确定唯一的所有者。'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: '是否对其他有问题的附件使用相同操作'
  },
  commands: {
    collectAttachmentsCurrentFolder: '收集当前文件夹中的附件',
    collectAttachmentsCurrentNote: '收集当前笔记中的附件',
    collectAttachmentsEntireVault: '收集整个库中的附件'
  },
  links: {
    documentation: '文档',
    tokens: '令牌'
  },
  menuItems: {
    collectAttachmentsInFile: '在文件中收集附件',
    collectAttachmentsInFiles: '在多个文件中收集附件'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: '正在为 \'{{noteFilePath}}\' 收集附件',
    collectingAttachmentsCancelled: '附件收集已取消。详情请查看控制台。',
    generatedAttachmentFileNameIsInvalid: '生成的附件文件名 \'{{path}}\' 无效。\n{{validationMessage}}\n请检查 {{settingName}} 设置。',
    notePathIsIgnored: '笔记路径已被忽略'
  },
  obsidianLib: {
    buttons: {
      cancel: '取消',
      ok: '确定'
    },
    dataview: {
      itemsPerPage: '每页项数:',
      jumpToPage: '跳转至页数:'
    },
    notices: {
      attachmentIsStillUsed: '附件 {{attachmentPath}} 仍然被其他笔记使用。它不会被删除。',
      unhandledError: '未处理的错误发生。请检查控制台以获取更多信息。'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: '所有文件都会被重命名。',
        displayText: '全部'
      },
      none: {
        description: '文件名保持不变。',
        displayText: '无'
      },
      onlyPastedImages: {
        description: '仅对粘贴的图片进行重命名。仅当 PNG 图像内容直接从剪贴板粘贴时适用。通常用于粘贴屏幕截图。',
        displayText: '仅粘贴的图片'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: '取消附件收集。',
        displayText: '取消'
      },
      copy: {
        description: '将附件复制到新位置。',
        displayText: '复制'
      },
      move: {
        description: '将附件移动到新位置。',
        displayText: '移动'
      },
      prompt: {
        description: '提示用户选择操作。',
        displayText: '提示'
      },
      skip: {
        description: '跳过附件并继续下一个。',
        displayText: '跳过'
      }
    },
    defaultImageSizeDimension: {
      height: '高度',
      width: '宽度'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// 自定义令牌已被注释掉，因为它们需要更新为插件 9.0.0 版本引入的新格式。\n// 更多信息请参考文档 ({{customTokensDocumentationUrl}})。',
      deprecated: '自定义令牌的注册格式已更改。请相应更新你的令牌。更多信息请参阅{{documentation}}。'
    },
    legacyRenameAttachmentsToLowerCase: '{{setting}} 设置已弃用。请改用 {{format}} 格式。更多信息请参阅{{documentation}}。',
    markdownUrlFormat: {
      deprecated: '你为 {{setting}} 格式设置的值可能不正确。更多信息请参阅{{documentation}}。此消息不会再次显示。'
    },
    specialCharacters: '{{setting}} 设置的默认值已更改。你的设置值已更新为新的默认值。',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: '默认图像大小必须为像素或百分比',
      invalidCustomTokensCode: '无效的自定义令牌代码',
      invalidRegularExpression: '无效的正则表达式 {{regExp}}',
      specialCharactersMustNotContainSlash: '特殊字符不能包含 /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: '特殊字符替换不能包含无效的文件名路径字符。'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: '附加文件时：',
      name: '附件重命名模式'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: '当收集的附件被多个笔记使用时：',
      name: '收集被多个笔记使用的附件模式'
    },
    collectedAttachmentFileName: {
      description: '查看可用的{{tokens}}。\n留空以保留附件当前的文件名。',
      name: '收集的附件文件名'
    },
    customTokens: {
      description: '要使用的自定义令牌。\n更多信息请参阅{{documentation}}。\n⚠️ 自定义令牌可以是任意 JavaScript 代码。如果编写不当，可能会导致数据丢失。使用风险自负。',
      name: '自定义令牌'
    },
    defaultImageSize: {
      description: '默认图像大小。\n可以用像素（{{pixels}}）或图像完整尺寸的百分比（{{percentage}}）指定。\n留空以使用原始图像大小。',
      name: '默认图像大小'
    },
    downloadNetworkImages: {
      description: '收集附件时，自动下载 Markdown 中引用的网络图片并保存到本地。',
      name: '下载网络图片'
    },
    duplicateNameSeparator: {
      description: '当你粘贴或拖入与现有文件同名的文件时，会在文件名中添加此分隔符。\n例如，当你拖入文件 {{existingFile}} 时，它会被重命名为 {{firstAvailableName}}、{{secondAvailableName}} 等，取第一个可用的名称。',
      name: '重复文件名分隔符'
    },
    excludePathsFromAttachmentCollecting: {
      description: '执行 {{command}} 命令时，排除以下路径中的附件。\n每行输入一个路径。\n{{pathSyntax}}\n如果设置为空，则不会从附件收集中排除任何路径。',
      name: '从附件收集中排除路径'
    },
    generatedAttachmentFileName: {
      description: '查看可用的{{tokens}}。',
      name: '生成的附件文件名'
    },
    jpegQuality: {
      description: '质量越低，压缩率越高。',
      name: 'JPEG 质量'
    },
    locationForNewAttachments: {
      description: '以 {{relativePrefix}} 开头表示相对于笔记所在文件夹的路径。\n查看可用的{{tokens}}。\n不推荐使用 {{dotFolder}} 这样的点文件夹，因为 Obsidian 不会跟踪它们。你可能需要使用 {{unhidePlugin}} 插件来管理它们。',
      name: '新附件位置'
    },
    markdownUrlFormat: {
      description: '添加附件时插入到 Markdown 中的 URL 格式。它只在插入的那一刻生效：之后笔记或附件被重命名或移动时，Obsidian 重写的链接会使用默认格式。\n查看可用的{{tokens}}。\n留空以使用默认格式。',
      name: 'Markdown URL 格式'
    },
    networkImageDownloadTimeoutInSeconds: {
      description: '下载每张网络图片的超时时间（秒）。',
      name: '网络图片下载超时时间（秒）'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: '是否将附件文件夹和文件名设置应用于其他插件创建的附件。\n有些插件不询问 Obsidian 附件应放在何处，直接以自己的命名把附件写入库中。启用此项后，这类文件一出现就会被移动并重命名。\n仅处理在打开笔记时创建、并且被笔记链接的文件：没有任何笔记链接的文件是其他插件自用的数据，会留在写入的位置。来自同步或库导入的文件绝不会被处理。\n{{modes}}\n创建文件的插件根据写入操作的调用栈来识别，这只是尽力而为：由 Obsidian 本身、同步客户端或延迟写入的插件写入的文件，无法识别出插件。这类文件视为不在下方列表中。',
      name: '重命名其他插件创建的附件'
    },
    renameAttachmentsToLowerCase: '将附件重命名为小写',
    renamedAttachmentFileName: {
      description: '查看可用的{{tokens}}。\n留空以保留附件当前的文件名。',
      name: '重命名的附件文件名'
    },
    resetToSampleCustomTokens: {
      message: '确定要将自定义令牌重置为示例自定义令牌吗？你的更改将会丢失。',
      title: '重置为示例自定义令牌'
    },
    shouldConvertPastedImagesToJpeg: {
      description: '是否将粘贴的图片转换为 JPEG。仅当 PNG 图像内容直接从剪贴板粘贴时适用。通常用于粘贴屏幕截图。',
      name: '是否将粘贴的图片转换为 JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: '如果启用，通过 {{command}} 命令处理的附件将根据 {{setting}} 设置重命名。',
      name: '是否重命名收集的附件'
    },
    specialCharacters: {
      description: '附件文件夹和文件名中要替换或删除的特殊字符。\n留空以保留特殊字符。',
      name: '特殊字符'
    },
    specialCharactersReplacement: {
      description: '附件文件夹和文件名中用于替换特殊字符的字符串。\n留空以删除特殊字符。',
      name: '特殊字符替换'
    },
    timeoutInSeconds: {
      description: '所有操作的超时时间（秒）。\n如果设置为 {{zero}}，则禁用操作执行超时。',
      name: '超时时间（秒）'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: '重命名附件文件',
    folderTitle: '选择附件文件夹',
    previewModal: {
      title: '预览附件文件 \'{{fullFileName}}\''
    },
    title: '为提示令牌提供一个值'
  },
  regularExpression: '/正则表达式/'
};
