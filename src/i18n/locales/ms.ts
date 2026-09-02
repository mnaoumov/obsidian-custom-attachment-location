export const ms = {
  attachmentCollector: {
    confirm: {
      part1: 'Adakah anda mahu mengumpul lampiran untuk semua nota dalam folder secara rekursif?',
      part2: 'Operasi ini tidak boleh dibatalkan.'
    },
    progressBar: {
      message: 'Mengumpul lampiran {{iterationString}} - \'{{noteFilePath}}\'.',
      title: 'Mengumpul lampiran...'
    }
  },
  buttons: {
    copy: 'Salin',
    move: 'Pindah',
    previewAttachmentFile: 'Pratonton fail lampiran',
    skip: 'Langkau'
  },
  collectAttachmentUsedByMultipleNotesModal: {
    content: {
      part1: 'Lampiran',
      part2: 'dirujuk oleh beberapa nota.'
    },
    heading: 'Mengumpul lampiran yang digunakan oleh beberapa nota',
    noPriorityWinnerReason: {
      EmptyList: 'Ia tidak dipindahkan kerana tetapan {{settingName}} kosong, jadi tiada apa-apa yang menentukan nota mana yang memilikinya.',
      NoMatch: 'Ia tidak dipindahkan kerana tiada satu pun daripada nota ini sepadan dengan mana-mana entri dalam tetapan {{settingName}}.',
      Tie: 'Ia tidak dipindahkan kerana beberapa daripada nota ini sepadan dengan tetapan {{settingName}} sama baiknya, jadi ia tidak menamakan satu pemilik.'
    },
    shouldUseSameActionForOtherProblematicAttachmentsToggle: 'Patut menggunakan tindakan yang sama untuk lampiran bermasalah lain'
  },
  commands: {
    collectAttachmentsCurrentFolder: 'Kumpul lampiran dalam folder semasa',
    collectAttachmentsCurrentNote: 'Kumpul lampiran dalam nota semasa',
    collectAttachmentsEntireVault: 'Kumpul lampiran dalam keseluruhan vault'
  },
  menuItems: {
    collectAttachmentsInFile: 'Kumpul lampiran dalam fail',
    collectAttachmentsInFiles: 'Kumpul lampiran dalam fail-fail'
  },
  notice: {
    collectingAttachments: 'Mengumpul lampiran untuk \'{{noteFilePath}}\'',
    collectingAttachmentsCancelled: 'Pengumpulan lampiran dibatalkan. Lihat konsol untuk butiran.',
    generatedAttachmentFileNameIsInvalid: {
      part1: 'Nama fail lampiran yang dijana \'{{path}}\' tidak sah.\n{{validationMessage}}\nSemak',
      part2: 'tetapan anda.'
    },
    notePathIsIgnored: 'Laluan nota diabaikan'
  },
  obsidianDevUtils: {
    buttons: {
      cancel: 'Batal',
      ok: 'OK'
    },
    dataview: {
      itemsPerPage: 'Item per halaman:',
      jumpToPage: 'Lompat ke halaman:'
    },
    notices: {
      attachmentIsStillUsed: 'Lampiran {{attachmentPath}} masih digunakan oleh nota lain. Ia tidak akan dipadamkan.',
      unhandledError: 'Ralat yang tidak diuruskan berlaku. Sila semak konsol untuk maklumat lanjut.'
    }
  },
  pluginSettings: {
    attachmentRenameMode: {
      all: {
        description: 'semua fail akan dinamakan semula.',
        displayText: 'Semua'
      },
      none: {
        description: 'nama mereka dipelihara.',
        displayText: 'Tiada'
      },
      onlyPastedImages: {
        description: 'hanya imej yang ditampal akan dinamakan semula. Berlaku hanya apabila kandungan imej PNG ditampal terus dari papan keratan. Biasanya, untuk menampal tangkapan skrin.',
        displayText: 'Hanya imej yang ditampal'
      }
    },
    collectAttachmentUsedByMultipleNotesMode: {
      cancel: {
        description: 'batalkan pengumpulan lampiran.',
        displayText: 'Batal'
      },
      copy: {
        description: 'salin lampiran ke lokasi baru.',
        displayText: 'Salin'
      },
      move: {
        description: 'pindahkan lampiran ke lokasi baru.',
        displayText: 'Pindah'
      },
      prompt: {
        description: 'minta pengguna memilih tindakan.',
        displayText: 'Minta'
      },
      skip: {
        description: 'langkau lampiran dan teruskan ke yang seterusnya.',
        displayText: 'Langkau'
      }
    },
    defaultImageSizeDimension: {
      height: 'Ketinggian',
      width: 'Kelebaran'
    }
  },
  pluginSettingsManager: {
    customToken: {
      codeComment: '// Token kustom telah dikomenkan kerana perlu dikemas kini ke format baharu yang diperkenalkan dalam versi pemalam 9.0.0.\n// Rujuk dokumentasi (https://github.com/mnaoumov/obsidian-custom-attachment-location?tab=readme-ov-file#custom-tokens) untuk maklumat lanjut.',
      deprecated: {
        part1: 'Dalam versi pemalam 9.0.0, format pendaftaran token kustom telah berubah. Sila kemas kini token anda dengan sewajarnya. Rujuk',
        part2: 'dokumentasi',
        part3: 'untuk maklumat lanjut'
      }
    },
    legacyRenameAttachmentsToLowerCase: {
      part1: 'Dalam versi pemalam 9.0.0, tetapan',
      part2: 'telah tidak digunakan lagi. Gunakan format',
      part3: 'sebaliknya. Lihat',
      part4: 'dokumentasi',
      part5: 'untuk maklumat lanjut'
    },
    markdownUrlFormat: {
      deprecated: {
        part1: 'Anda mungkin mempunyai nilai yang tidak betul untuk format',
        part2: '. Sila rujuk',
        part3: 'dokumentasi',
        part4: 'untuk maklumat lanjut',
        part5: 'Mesej ini tidak akan dipaparkan lagi.'
      }
    },
    specialCharacters: {
      part1: 'Dalam versi pemalam 9.16.0, nilai tetapan lalai',
      part2: 'telah berubah. Nilai tetapan anda telah dikemas kini ke nilai lalai baharu.'
    },
    validation: {
      defaultImageSizeMustBePercentageOrPixels: 'Saiz imej lalai mesti dalam piksel atau peratusan',
      invalidCustomTokensCode: 'Kod token kustom tidak sah',
      invalidRegularExpression: 'Ungkapan biasa tidak sah {{regExp}}',
      specialCharactersMustNotContainSlash: 'Aksara khas tidak boleh mengandungi /',
      specialCharactersReplacementMustNotContainInvalidFileNamePathCharacters: 'Penggantian aksara khas tidak boleh mengandungi aksara laluan nama fail yang tidak sah.'
    }
  },
  pluginSettingsTab: {
    attachmentRenameMode: {
      description: {
        part1: 'Apabila melampirkan fail:'
      },
      name: 'Mod penamaan semula lampiran'
    },
    collectAttachmentUsedByMultipleNotesMode: {
      description: {
        part1: 'Apabila lampiran yang dikumpulkan digunakan oleh beberapa nota:'
      },
      name: 'Mod pengumpulan lampiran yang digunakan oleh beberapa nota'
    },
    collectedAttachmentFileName: {
      description: {
        part1: 'Lihat token',
        part2: 'yang tersedia'
      },
      name: 'Nama fail lampiran yang dikumpulkan'
    },
    customTokens: {
      description: {
        part1: 'Token kustom yang akan digunakan.',
        part2: 'Lihat',
        part3: 'dokumentasi',
        part4: 'untuk maklumat lanjut.',
        part5: '⚠️ Token kustom boleh menjadi kod JavaScript sewenang-wenangnya. Jika ditulis dengan buruk, ia boleh menyebabkan kehilangan data. Gunakan dengan risiko sendiri.'
      },
      name: 'Token kustom'
    },
    defaultImageSize: {
      description: {
        part1: 'Saiz imej lalai.',
        part2: 'Boleh dinyatakan dalam piksel',
        part3: 'atau sebagai peratusan daripada saiz imej penuh',
        part4: 'Biarkan kosong untuk menggunakan saiz asal.'
      },
      name: 'Saiz imej lalai'
    },
    duplicateNameSeparator: {
      description: {
        part1: 'Apabila anda menampal/menyeret fail dengan nama yang sama seperti fail yang sedia ada, pemisah ini akan ditambah pada nama fail.',
        part2: 'Contohnya, apabila anda menyeret fail',
        part3: ', ia akan dinamakan semula kepada',
        part4: ', dll, mendapat nama pertama yang tersedia.'
      },
      name: 'Pemisah nama pendua'
    },
    excludePathsFromAttachmentCollecting: {
      description: {
        part1: 'Kecualikan lampiran dari laluan berikut apabila',
        part2: 'Kumpul lampiran',
        part3: 'arahan dilaksanakan.',
        part4: 'Masukkan setiap laluan pada baris baru.',
        part5: 'Anda boleh menggunakan rentetan laluan atau',
        part6: 'Jika tetapan kosong, tiada laluan dikecualikan dari pengumpulan lampiran.'
      },
      name: 'Kecualikan laluan dari pengumpulan lampiran'
    },
    generatedAttachmentFileName: {
      description: {
        part1: 'Lihat token',
        part2: 'yang tersedia'
      },
      name: 'Nama fail lampiran yang dijana'
    },
    jpegQuality: {
      description: 'Semakin kecil kualiti, semakin besar nisbah mampatan.',
      name: 'Kualiti JPEG'
    },
    locationForNewAttachments: {
      description: {
        part1: 'Mulakan dengan',
        part2: 'untuk menggunakan laluan relatif.',
        part3: 'Lihat token',
        part4: 'yang tersedia',
        part5: 'Folder titik seperti',
        part6: 'tidak disyorkan, kerana Obsidian tidak menjejaki mereka. Anda mungkin perlu menggunakan',
        part7: 'Pemalam untuk mengurusnya.'
      },
      name: 'Lokasi untuk lampiran baharu'
    },
    markdownUrlFormat: {
      description: {
        part1: 'Format untuk URL yang akan dimasukkan ke dalam Markdown.',
        part2: 'Lihat token',
        part3: 'yang tersedia',
        part4: 'Biarkan kosong untuk menggunakan format lalai.'
      },
      name: 'Format URL Markdown'
    },
    renameAttachmentsToLowerCase: 'Nama semula lampiran kepada huruf kecil',
    renamedAttachmentFileName: {
      description: {
        part1: 'Lihat token',
        part2: 'yang tersedia'
      },
      name: 'Nama fail lampiran yang dinamakan semula'
    },
    resetToSampleCustomTokens: {
      message: 'Adakah anda pasti mahu menetapkan semula token kustom kepada token kustom sampel? Perubahan anda akan hilang.',
      title: 'Tetapkan semula kepada token kustom sampel'
    },
    shouldConvertPastedImagesToJpeg: {
      description: 'Sama ada untuk menukar imej yang ditampal kepada JPEG. Berlaku hanya apabila kandungan imej PNG ditampal terus dari papan keratan. Biasanya, untuk menampal tangkapan skrin.',
      name: 'Sama ada menukar imej yang ditampal kepada JPEG'
    },
    shouldRenameAttachmentsCreatedByOtherPlugins: {
      description: {
        part1: 'Sama ada tetapan folder lampiran dan nama fail dikenakan pada lampiran yang dicipta oleh pemalam LAIN.',
        part2: 'Sesetengah pemalam menulis lampiran terus ke dalam bilik kebal dengan nama pilihan sendiri, tanpa bertanya kepada Obsidian di mana tempatnya. Dengan ini dihidupkan, fail sebegitu dipindahkan dan dinamakan semula sebaik ia muncul.',
        part3: 'Hanya fail yang dicipta semasa sesuatu nota dibuka disentuh, bukan fail yang tiba daripada penyegerakan atau import bilik kebal.'
      },
      name: 'Namakan semula lampiran yang dicipta pemalam lain'
    },
    shouldRenameCollectedAttachments: {
      description: {
        part1: 'Jika diaktifkan, lampiran yang diproses melalui',
        part2: 'Kumpul lampiran',
        part3: 'arahan akan dinamakan semula mengikut',
        part4: 'tetapan.'
      },
      name: 'Sama ada menamakan semula lampiran yang dikumpulkan'
    },
    specialCharacters: {
      description: {
        part1: 'Aksara khas dalam folder lampiran dan nama fail yang akan diganti atau dialihkan.',
        part2: 'Biarkan kosong untuk memelihara aksara khas.'
      },
      name: 'Aksara khas'
    },
    specialCharactersReplacement: {
      description: {
        part1: 'Rentetan penggantian untuk aksara khas dalam folder lampiran dan nama fail.',
        part2: 'Biarkan kosong untuk mengalihkan aksara khas.'
      },
      name: 'Penggantian aksara khas'
    },
    timeoutInSeconds: {
      description: {
        part1: 'Masa tamat dalam saat untuk semua operasi.',
        part2: 'Jika',
        part3: 'ditetapkan, masa tamat pelaksanaan operasi dilumpuhkan.'
      },
      name: 'Masa tamat dalam saat'
    }
  },
  promptWithPreviewModal: {
    fileNameTitle: 'Namakan semula fail lampiran',
    folderTitle: 'Pilih folder lampiran',
    previewModal: {
      title: 'Pratonton fail lampiran \'{{fullFileName}}\''
    },
    title: 'Berikan nilai untuk token prompt'
  },
  regularExpression: '/ungkapan biasa/'
};
