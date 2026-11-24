export const vi = {
  attachmentCollector: {
    confirm: 'Bạn có muốn thu thập tệp đính kèm cho tất cả ghi chú trong các thư mục, bao gồm cả thư mục con, không?\n{{folders}}\nThao tác này không thể hoàn tác.',
    progressBar: {
      message: 'Đang thu thập tệp đính kèm {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Đang thu thập tệp đính kèm...'
    }
  },
  buttons: {
    copy: 'Sao chép',
    move: 'Di chuyển',
    previewAttachmentFile: 'Xem trước tệp đính kèm',
    skip: 'Bỏ qua'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: 'Tệp đính kèm {{attachment}} được nhiều ghi chú tham chiếu.',
    heading: 'Thu thập tệp đính kèm được sử dụng bởi nhiều ghi chú',
    noPriorityWinnerReason: {
      EmptyList: 'Tệp không được di chuyển vì cài đặt {{settingName}} trống, nên không có gì quyết định ghi chú nào trong số này sở hữu nó.',
      NoMatch: 'Tệp không được di chuyển vì không ghi chú nào trong số này khớp với bất kỳ mục nào trong cài đặt {{settingName}}.',
      Tie: 'Tệp không được di chuyển vì nhiều ghi chú trong số này khớp với cài đặt {{settingName}} như nhau, nên không xác định được một chủ sở hữu duy nhất.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Nên sử dụng cùng một hành động cho các tệp đính kèm có vấn đề khác'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Thu thập tệp đính kèm trong thư mục hiện tại',
    collectAttachmentsCurrentNote: 'Thu thập tệp đính kèm trong ghi chú hiện tại',
    collectAttachmentsEntireVault: 'Thu thập tệp đính kèm trong toàn bộ kho'
  },
  links: {
    documentation: 'tài liệu',
    tokens: 'token'
  },
  menuItems: {
    collectAttachmentsInFile: 'Thu thập tệp đính kèm trong tệp',
    collectAttachmentsInFiles: 'Thu thập tệp đính kèm trong các tệp'
  },
  notice: {
    attachmentFileNameShortened: 'The attachment file name was too long for the file system, so it was shortened to \'{{fileName}}\'. To choose how a long name is shortened, use the `trim` format option in your file name template.',
    collectingAttachments: 'Đang thu thập tệp đính kèm cho \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Thu thập tệp đính kèm đã bị hủy. Xem console để biết chi tiết.',
    generatedAttachmentFileNameIsInvalid: 'Tên tệp đính kèm được tạo \'{{path}}\' không hợp lệ.\n{{validationMessage}}\nHãy kiểm tra cài đặt {{settingName}} của bạn.',
    notePathIsIgnored: 'Đường dẫn ghi chú bị bỏ qua'
  },
  obsidianLib: {
    buttons: {
      cancel: 'Hủy',
      ok: 'Đồng ý'
    },
    dataview: {
      itemsPerPage: 'Mục trên mỗi trang:',
      jumpToPage: 'Chuyển đến trang:'
    },
    notices: {
      attachmentIsStillUsed: 'Tệp đính kèm {{attachmentPath}} vẫn đang được sử dụng bởi các ghi chú khác. Nó sẽ không bị xóa.',
      unhandledError: 'Đã xảy ra lỗi không xử lý được. Vui lòng kiểm tra console để biết thêm thông tin.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'Tất cả các tệp được đổi tên.',
        displayText: 'Tất cả'
      },
      none: {
        description: 'Tên của chúng được bảo tồn.',
        displayText: 'Không'
      },
      onlyPastedImages: {
        description: 'Chỉ các hình ảnh được dán mới được đổi tên. Chỉ áp dụng khi nội dung hình ảnh PNG được dán trực tiếp từ clipboard. Thông thường dùng để dán ảnh chụp màn hình.',
        displayText: 'Chỉ hình ảnh được dán'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'Hủy việc thu thập tệp đính kèm.',
        displayText: 'Hủy'
      },
      copy: {
        description: 'Sao chép tệp đính kèm đến vị trí mới.',
        displayText: 'Sao chép'
      },
      move: {
        description: 'Di chuyển tệp đính kèm đến vị trí mới.',
        displayText: 'Di chuyển'
      },
      prompt: {
        description: 'Nhắc người dùng chọn hành động.',
        displayText: 'Nhắc'
      },
      skip: {
        description: 'Bỏ qua tệp đính kèm và tiếp tục đến cái tiếp theo.',
        displayText: 'Bỏ qua'
      }
    },
    defaultImageSizeDimension: {
      height: 'Сhiều cao',
      width: 'Сhiều rộng'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Các token tùy chỉnh bị chú thích vì cần cập nhật theo định dạng mới được giới thiệu trong phiên bản plugin 9.0.0.\n// Vui lòng tham khảo tài liệu ({{customTokensDocumentationUrl}}) để biết thêm thông tin.',
      deprecated: 'Định dạng đăng ký token tùy chỉnh đã thay đổi. Vui lòng cập nhật các token của bạn cho phù hợp. Tham khảo {{documentation}} để biết thêm thông tin.'
    },
    legacyRenameAttachmentsToLowerCase: 'Cài đặt {{setting}} đã bị ngừng hỗ trợ. Hãy dùng định dạng {{format}} thay thế. Xem {{documentation}} để biết thêm thông tin.',
    markdownUrlFormat: {
      deprecated: 'Bạn có thể đã đặt một giá trị không chính xác cho định dạng {{setting}}. Vui lòng tham khảo {{documentation}} để biết thêm thông tin. Thông báo này sẽ không hiển thị lại.'
    },
    specialCharacters: 'Giá trị mặc định của cài đặt {{setting}} đã được thay đổi. Giá trị cài đặt của bạn đã được cập nhật theo giá trị mặc định mới.',
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Kích thước hình ảnh mặc định phải được tính bằng pixel hoặc phần trăm',
      invalidCustomTokensCode: 'Mã token tùy chỉnh không hợp lệ',
      invalidRegularExpression: 'Biểu thức chính quy không hợp lệ {{regExp}}',
      specialCharactersMustNotContainSlash: 'Ký tự đặc biệt không được chứa dấu /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Chuỗi thay thế ký tự đặc biệt không được chứa ký tự tên tệp hoặc đường dẫn không hợp lệ.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: 'Khi đính kèm tệp:',
      name: 'Chế độ đổi tên tệp đính kèm'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: 'Khi tệp đính kèm được thu thập được sử dụng bởi nhiều ghi chú:',
      name: 'Chế độ thu thập tệp đính kèm được sử dụng bởi nhiều ghi chú'
    },
    collectedAttachmentFileName: {
      description: 'Xem các {{tokens}} có sẵn.\nĐể trống để giữ nguyên tên tệp đính kèm hiện tại.',
      name: 'Tên tệp đính kèm được thu thập'
    },
    customTokens: {
      description: 'Các token tùy chỉnh để sử dụng.\nXem {{documentation}} để biết thêm thông tin.\n⚠️ Token tùy chỉnh có thể là mã JavaScript tùy ý. Nếu viết không cẩn thận, nó có thể gây mất dữ liệu. Bạn tự chịu rủi ro khi sử dụng.',
      name: 'Token tùy chỉnh'
    },
    defaultImageSize: {
      description: 'Kích thước hình ảnh mặc định.\nCó thể chỉ định bằng pixel ({{pixels}}) hoặc phần trăm kích thước đầy đủ của hình ảnh ({{percentage}}).\nĐể trống để sử dụng kích thước gốc của hình ảnh.',
      name: 'Kích thước hình ảnh mặc định'
    },
    duplicateNameSeparator: {
      description: 'Khi bạn dán hoặc kéo một tệp có cùng tên với một tệp đã tồn tại, bộ phân cách này sẽ được thêm vào tên tệp.\nVí dụ, khi bạn kéo tệp {{existingFile}}, nó sẽ được đổi tên thành {{firstAvailableName}}, {{secondAvailableName}}, v.v., lấy tên đầu tiên còn trống.',
      name: 'Bộ phân cách tên trùng'
    },
    excludePathsFromAttachmentCollecting: {
      description: 'Loại trừ tệp đính kèm từ các đường dẫn sau khi lệnh {{command}} được thực thi.\nNhập mỗi đường dẫn trên một dòng mới.\n{{pathSyntax}}\nNếu cài đặt để trống, không đường dẫn nào bị loại trừ khỏi việc thu thập tệp đính kèm.',
      name: 'Loại trừ đường dẫn khi thu thập tệp đính kèm'
    },
    generatedAttachmentFileName: {
      description: 'Xem các {{tokens}} có sẵn.',
      name: 'Tên tệp đính kèm được tạo'
    },
    jpegQuality: {
      description: 'Chất lượng càng thấp, tỷ lệ nén càng cao.',
      name: 'Chất lượng JPEG'
    },
    locationForNewAttachments: {
      description: 'Bắt đầu với {{relativePrefix}} để dùng đường dẫn tương đối so với thư mục cha của ghi chú.\nXem các {{tokens}} có sẵn.\nKhông nên dùng các thư mục bắt đầu bằng dấu chấm như {{dotFolder}}, vì Obsidian không theo dõi chúng. Bạn có thể cần dùng plugin {{unhidePlugin}} để quản lý chúng.',
      name: 'Vị trí tệp đính kèm mới'
    },
    markdownUrlFormat: {
      description: 'Định dạng URL được chèn vào Markdown khi thêm tệp đính kèm. Định dạng này chỉ áp dụng tại thời điểm đó: liên kết mà Obsidian viết lại sau này, khi ghi chú hoặc tệp đính kèm được đổi tên hay di chuyển, sẽ dùng định dạng mặc định.\nXem các {{tokens}} có sẵn.\nĐể trống để sử dụng định dạng mặc định.',
      name: 'Định dạng URL Markdown'
    },
    renameAttachmentsCreatedByOtherPluginsMode: {
      description: 'Có áp dụng các thiết lập thư mục đính kèm và tên tệp cho những tệp đính kèm do plugin KHÁC tạo hay không.\nMột số plugin ghi thẳng tệp đính kèm vào kho với tên của riêng chúng, mà không hỏi Obsidian xem nó thuộc về đâu. Khi bật tùy chọn này, tệp như vậy sẽ được di chuyển và đổi tên ngay sau khi xuất hiện.\nChỉ những tệp được tạo khi đang mở một ghi chú và được một ghi chú liên kết tới mới bị tác động: tệp không được ghi chú nào liên kết tới là dữ liệu mà plugin khác giữ cho riêng mình, và nó được giữ nguyên ở nơi đã được ghi. Tệp đến từ đồng bộ hoặc nhập kho không bao giờ bị tác động.\n{{modes}}\nPlugin tạo tệp được xác định từ ngăn xếp lời gọi của thao tác ghi. Việc này chỉ ở mức cố gắng tốt nhất: không xác định được plugin nào cho tệp do chính Obsidian, ứng dụng đồng bộ hoặc plugin trì hoãn việc ghi tạo ra. Tệp như vậy được coi là KHÔNG nằm trong danh sách bên dưới.',
      name: 'Đổi tên tệp đính kèm do plugin khác tạo'
    },
    renameAttachmentsToLowerCase: 'Đổi tên tệp đính kèm thành chữ thường',
    renamedAttachmentFileName: {
      description: 'Xem các {{tokens}} có sẵn.\nĐể trống để giữ nguyên tên tệp đính kèm hiện tại.',
      name: 'Tên tệp đính kèm được đổi tên'
    },
    resetToSampleCustomTokens: {
      message: 'Bạn có chắc muốn đặt lại token tùy chỉnh về token mẫu? Mọi thay đổi sẽ bị mất.',
      title: 'Đặt lại token mẫu'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Có nên chuyển đổi hình ảnh dán sang định dạng JPEG không. Chỉ áp dụng khi nội dung ảnh PNG được dán trực tiếp từ clipboard. Thường dùng cho ảnh chụp màn hình.',
      name: 'Chuyển hình ảnh dán sang JPEG'
    },
    shouldRenameCollectedAttachments: {
      description: 'Nếu bật, các tệp đính kèm được xử lý qua các lệnh {{command}} sẽ được đổi tên theo cài đặt {{setting}}.',
      name: 'Đổi tên tệp đính kèm đã thu thập'
    },
    specialCharacters: {
      description: 'Các ký tự đặc biệt trong tên thư mục và tệp đính kèm sẽ được thay thế hoặc loại bỏ.\nĐể trống để giữ nguyên các ký tự đặc biệt.',
      name: 'Ký tự đặc biệt'
    },
    specialCharactersReplacement: {
      description: 'Chuỗi thay thế cho các ký tự đặc biệt trong tên thư mục và tệp đính kèm.\nĐể trống để loại bỏ các ký tự đặc biệt.',
      name: 'Thay thế ký tự đặc biệt'
    },
    timeoutInSeconds: {
      description: 'Thời gian chờ tính bằng giây cho tất cả các thao tác.\nNếu đặt là {{zero}}, thời gian chờ thực thi thao tác sẽ bị vô hiệu hóa.',
      name: 'Thời gian chờ (giây)'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Đổi tên tệp đính kèm',
    folderTitle: 'Chọn thư mục đính kèm',
    previewModal: {
      title: 'Xem trước tệp đính kèm \'{{fullFileName}}\''
    },
    title: 'Cung cấp giá trị cho token nhắc nhở'
  },
  regularExpression: '/biểu thức chính quy/'
};
